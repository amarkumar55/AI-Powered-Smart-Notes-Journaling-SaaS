import logging
import uuid
from django.db.models import Min
from django.db.models import F
from django.db import transaction
from rest_framework import status
from apis.api_auth.models import Wallet
from rest_framework.views import APIView
from .models import Note, UserNoteLibrary
from .permissions import IsOwnerOrReadOnly
from rest_framework.response import Response
from django.utils.dateparse import parse_date
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound
from .serializers import UserNoteLibrarySerializer
from django_ratelimit.decorators import ratelimit
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import IsAuthenticated
from .models import Note, NoteLike, NoteComment, NoteChatLog
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.generics import RetrieveUpdateDestroyAPIView, ListAPIView, ListCreateAPIView, DestroyAPIView
from django.http import StreamingHttpResponse
import json
from core.chat_service import prepare_chat_context, handle_ai_chat
from functools import reduce
from operator import or_
from django.db.models import  F, Q



from .serializers import (
    NoteSerializer,
    NoteCommentSerializer,
    NoteSummarySerializer,
    NoteChatLogSerializer
)

from apis.api_auth.utlity import  enforce_csrf_if_web 


from core.note_processor import (
    process_audio_and_generate_note,
    process_image_and_generate_note,
    ask_ai_with_note,
    summarize_chunks,
    summarize_text,
    count_tokens,
    TOKEN_COSTS
)

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteListCreate(ListCreateAPIView):
    """
    - Uses serializer-driven image & tag handling (uploaded_images field).
    - Validates files (size/type) in serializer.
    - Enforces CSRF for web cookie clients (only for mutating requests).
    - Performs wallet debit atomically for AI-powered creations.
    - Keeps view thin: heavy AI work can be offloaded to background.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = NoteSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser] 
    def initial(self, request, *args, **kwargs):
        """
        Called before dispatching to handler methods.
        Use enforce_csrf_if_web to protect cookie-based clients while allowing token-based clients.
        """
        maybe = enforce_csrf_if_web(request)
        if maybe is not None:
            # enforce_csrf_if_web returns a Response when CSRF check fails; return it directly.
            return maybe
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
    
        notes = Note.objects.filter(user=user).select_related("user")
    
        sort_by = self.request.query_params.get("sort_by", "-created_at")
        is_publish = self.request.query_params.get("is_publish")
        search = self.request.query_params.get("search", "")

        if search:
            terms = [term.strip() for term in search.split() if term.strip()]
            notes = notes.filter(
                reduce(or_, [Q(title__icontains=t) | Q(content__icontains=t) for t in terms])
            )

        # Exclude drafts by default
        if is_publish is not None:
            is_publish_bool = str(is_publish).lower() in ["1", "true", "yes"]
            notes = notes.filter(is_publish=is_publish_bool)
        else:
            notes = notes.filter(is_publish=True)

        # Validate sort field
        valid_sort_fields = ["created_at", "-created_at", "title", "-title"]
        if sort_by not in valid_sort_fields:
            sort_by = "-created_at"

        return notes.order_by(sort_by)
    

    @transaction.atomic
    def perform_create(self, serializer):
        """
        Business logic:
         - For plain text notes: create via serializer (serializer handles uploaded_images & tags).
         - For audio/image note types: debit user wallet (atomic); process (sync or enqueue); then save results from processing.
        Important:
         - The serializer should include uploaded_images (list of ImageFields) so file uploads are validated there.
         - Avoid returning raw exception strings to clients.
        """
        req = self.request
        data = req.data
        note_type = data.get("type", "text")
        audio = req.FILES.get("audio") or data.get("audio")
        image = req.FILES.get("image") or data.get("image")
        title = (data.get("title") or "").strip()
        public = data.get("is_public", False)
        publish = data.get("is_publish", False)
        target_lang = data.get("lang", "en")

        # Basic validation (size checks for direct audio/image; uploaded_images validated in serializer)
        if audio and getattr(audio, "size", 0) > 10 * 1024 * 1024:
            raise ValidationError({"error": "Audio file too large (max 10MB)"})
        if image and getattr(image, "size", 0) > 1 * 1024 * 1024:
            raise ValidationError({"error": "Image file too large (max 5MB)"})

        wallet =  Wallet.objects.get(user=req.user)

        try:
            # TEXT note: serializer handles uploaded_images & tags; model generates slug
            if note_type == "text":
                # require either title or content (serializer validation can also enforce)
                serializer.save(user=req.user, type="text", is_public=public)
                return

            # AUDIO note: cost, then generate title/content via processor (prefer background)
            if note_type in ("live_audio", "uploaded_audio"):
                if not wallet.debit_tokens(TOKEN_COSTS["audio_note"], description="audio_note_generation"):
                    raise ValidationError({"error": "Insufficient tokens for audio note"})

                # Option A (recommended): enqueue background task that:
                #   - calls process_audio_and_generate_note,
                #   - saves title & content to the note,
                #   - notifies user when ready.
                #
                # Option B (current): do synchronous processing (may increase response time).
                note_data = process_audio_and_generate_note(audio, target_lang)

                serializer.save(
                    user=req.user,
                    title=note_data.get("title"),
                    content=note_data.get("summary"),
                    type=note_type,
                    is_public=public,
                    is_publish=publish,
                )
                return

            # IMAGE note: cost + processing
            if note_type == "image":
                if not wallet.debit_tokens(TOKEN_COSTS["image_note"], description="image_note_generation"):
                    raise ValidationError({"error": "Insufficient tokens for image note"})

                # same enqueue recommendation as audio above
                note_data = process_image_and_generate_note(image)

                serializer.save(
                    user=req.user,
                    title=note_data.get("title"),
                    content=note_data.get("summary"),
                    type="image",
                    is_public=public,
                )
                return

            raise ValidationError({"error": "Invalid note type or missing file."})

        except ValidationError:
            # re-raise DRF/Django validation errors as-is
            raise
        except Exception:  # don't leak internal errors
            logger.exception("Note creation failed")
            # If wallet was debited and creation failed after debit, consider refund logic here.
            raise ValidationError({"error": "Failed to create note. Please try again later."})


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteDetail(RetrieveUpdateDestroyAPIView):
    queryset = Note.objects.all().select_related("user")
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    lookup_field = "slug"

    def retrieve(self, request, *args, **kwargs):
        note = self.get_object()
        Note.objects.filter(pk=note.pk).update(views_count=F("views_count") + 1)
        serializer = self.get_serializer(note)
        return Response(serializer.data)
    

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteLikeToggle(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        note = get_object_or_404(Note, slug=slug)
        print(note)
        
        like, created = NoteLike.objects.get_or_create(user=request.user, note=note)
    
        if created:
            Note.objects.filter(pk=note.pk).update(likes_count=F("likes_count") + 1)
    
        if not created:
            like.delete()
            Note.objects.filter(pk=note.pk).update(likes_count=F("likes_count") - 1)
            return Response({"liked": False})
        
        return Response({"liked": True})


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteCommentCreate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        note = get_object_or_404(Note, slug=slug)
        content = request.data.get("content")
    
        if not content:
            return Response({"error": "Content required"}, status=400)
        try:
            comment = NoteComment.objects.create(user=request.user, note=note, content=content)
            Note.objects.filter(pk=note.pk).update(comments_count=F("comments_count") + 1)
            serializer = NoteCommentSerializer(comment)
            return Response(serializer.data, status=200)
        except Exception:
            logger.exception("Unable to add comment")
            return Response({"error": "Unable to add comment"}, status=500)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class NoteCommentDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        return get_object_or_404(NoteComment, pk=pk, user=user)

    def put(self, request, pk):
        """Edit a comment"""
        comment = self.get_object(pk, request.user)
        content = request.data.get("content")
        if not content:
            return Response({"error": "Content required"}, status=400)

        comment.content = content
        comment.save(update_fields=["content", "updated_at"])
        serializer = NoteCommentSerializer(comment)
        return Response(serializer.data, status=200)

    def delete(self, request, pk):
        """Delete a comment"""
        comment = self.get_object(pk, request.user)
        note_id = comment.note_id
        comment.delete()
        # decrement comments_count
        Note.objects.filter(pk=note_id).update(comments_count=F("comments_count") - 1)
        return Response({"success": True}, status=200)
    

@method_decorator(ratelimit(key="user_or_ip", rate="2/m", block=True), name="dispatch")
class NoteCommentList(ListAPIView):
    serializer_class = NoteCommentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        slug = self.kwargs.get("slug")
        note = get_object_or_404(Note, slug=slug)
        return NoteComment.objects.filter(note=note).select_related("user").order_by("-created_at")

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteShare(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
        maybe_csrf = enforce_csrf_if_web(request)
    
        if maybe_csrf is not None:
            return maybe_csrf

        note = get_object_or_404(Note, slug=slug)
        Note.objects.filter(pk=note.pk).update(shares_count=F("shares_count") + 1)
        note.refresh_from_db(fields=["shares_count"])
        shareable_link = request.build_absolute_uri(f"/public/note-details/{note.slug}/")
        
        return Response(
            {"message": "Note shared successfully", "shareable_link": shareable_link, "shares_count": note.shares_count},
            status=200,
        )

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class UserNoteLibraryListCreateView(ListCreateAPIView):
    serializer_class = UserNoteLibrarySerializer
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        maybe = enforce_csrf_if_web(request)
        if maybe is not None:
            return maybe
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        """
        Return user’s saved notes, optionally filtered by search query.
        """
        search = self.request.query_params.get("search", "").strip()
        qs = (
            UserNoteLibrary.objects.filter(user=self.request.user)
            .select_related("note")
            .order_by("-created_at")
        )

        if search:
            qs = qs.filter(Q(note__title__icontains=search))

        return qs

    def list(self, request, *args, **kwargs):
        only_ids = request.query_params.get("only_ids")
        if only_ids and only_ids.lower() in ["1", "true", "yes"]:
            note_slugs = (
                UserNoteLibrary.objects.filter(user=request.user)
                .values_list("note__slug", flat=True)
            )
            return Response(list(note_slugs))  
        
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """
        Save a note by slug to user's library. Prevent duplicates.
        """
        slug = request.data.get("slug")
        
        if not slug:
            return Response({"error": "slug is required."}, status=status.HTTP_400_BAD_REQUEST)

        note = get_object_or_404(Note, slug=slug)

        obj, created = UserNoteLibrary.objects.get_or_create(user=request.user, note=note)

        if created:
            serializer = self.get_serializer(obj)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"message": "Note already in library."}, status=status.HTTP_200_OK)

@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class UserNoteLibraryDeleteView(DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserNoteLibrarySerializer

    def delete(self, request, slug, *args, **kwargs):
        """
        Remove a note from the library by slug.
        """
        note = get_object_or_404(Note, slug=slug)
        obj = UserNoteLibrary.objects.filter(user=request.user, note=note).first()
        if not obj:
            return Response({"error": "Note not found in your library."}, status=status.HTTP_404_NOT_FOUND)

        obj.delete()
        return Response({"message": "Note removed from library."}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteSummarizeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        note = get_object_or_404(Note, slug=slug, user=request.user)
        try:
            result = summarize_text(note.content)
            serializer = NoteSummarySerializer(data=result)
            if serializer.is_valid():
                return Response(serializer.data, status=200)
            return Response(serializer.errors, status=400)
        except Exception:
            logger.exception("Failed to summarize note")
            return Response({"error": "Failed to summarize note"}, status=500)
        
@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")        
class NoteChatSession(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
    
        note = get_object_or_404(Note, slug=slug)

        # Check permissions for private notes
        if not note.is_public and note.user != request.user:
            return Response({"error": "You cannot start a chat with this private note."}, status=403)

        # Generate session_id
        session_id = uuid.uuid4()

        # (Optional) Persist session metadata if you want to track sessions separately
        # For now, we'll just return the session_id, and each NoteChatLog entry will reference it.

        return Response(
            {
                "session_id": str(session_id),
                "note": slug,
                "message_limit": 20,
            },
            status=201,
        )
    
@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class NoteChatView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, slug, session_id):
        """
        Fetch the chat history for a given session_id under a note.
        """
        note = get_object_or_404(Note, slug=slug)
        if not note.is_public and note.user != request.user:
            return Response({"error": "You cannot view chats for this private note."}, status=403)

        # validate session_id
        try:
            session_id = uuid.UUID(str(session_id))
        except ValueError:
            return Response({"error": "Invalid session_id"}, status=400)

        # fetch all messages for this session
        logs = note.chat_logs.filter(session_id=session_id).order_by("created_at")

        serializer = NoteChatLogSerializer(logs, many=True)
        return Response({"session_id": str(session_id), "messages": serializer.data}, status=200)


    def post(self, request, slug, session_id):

        maybe_csrf = enforce_csrf_if_web(request)
    
        if maybe_csrf is not None:
            return maybe_csrf

        note = get_object_or_404(Note, slug=slug)
        
        if not note.is_public and note.user != request.user:
            return Response({"error": "You cannot chat with this private note."}, status=403)

        user_message = request.data.get("message")
        
        if not user_message:
            return Response({"error": "Message is required."}, status=400)

        # validate session_id
        try:
            session_id = uuid.UUID(str(session_id))
        except ValueError:
            return Response({"error": "Invalid session_id"}, status=400)

        try:
            note, wallet, chat_history, note_content, session_id, total_tokens = prepare_chat_context(
            request.user, slug, session_id, request.data.get("message")
        )
        except Exception as e:
            return Response({"error": str(e)}, status=400)

        def stream():
            for payload in handle_ai_chat(note, request.user, session_id,
                                        request.data["message"], note_content,
                                        wallet, chat_history):
                yield f"data: {json.dumps(payload)}\n\n"

        return StreamingHttpResponse(stream(), content_type="text/event-stream")

@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class NoteChatHistoryView(ListAPIView):
    """
    Returns sessions of chat history for a note.
    Each session includes:
      - session_id
      - title (first user message of the session)
      - created_at (first message time)
    """
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        slug = self.kwargs.get("slug")
        note = get_object_or_404(Note.objects.select_related("user"), slug=slug)

        if not note.is_public and note.user_id != self.request.user.id:
            raise NotFound("Access denied.")

        # Group by session_id and pick first user_message as title
        qs = (
            NoteChatLog.objects.filter(note=note)
            .values("session_id")
            .annotate(
                first_message=Min("user_message"),
                created_at=Min("created_at"),
            )
            .order_by("-created_at")  # latest session first
        )
        return qs

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        # DRF pagination still works because queryset is values() with annotate
        page = self.paginate_queryset(queryset)
        results = page if page is not None else queryset

        sessions = [
            {
                "session_id": str(item["session_id"]),
                "title": item["first_message"][:50] if item["first_message"] else "Untitled",
                "created_at": item["created_at"],
            }
            for item in results
        ]

        if page is not None:
            return self.get_paginated_response(sessions)

        return Response(sessions, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteChatClearSession(APIView):
    """
    Deletes all chat logs belonging to a specific session of a note.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, slug, session_id):
        note = get_object_or_404(Note.objects.select_related("user"), slug=slug)

        if not note.is_public and note.user_id != request.user.id:
            raise NotFound("Access denied.")

        deleted, _ = NoteChatLog.objects.filter(note=note, session_id=session_id).delete()
        if deleted == 0:
            return Response({"message": "No chat logs found for this session."}, status=404)

        return Response({"message": f"Deleted {deleted} messages for session {session_id}."}, status=200)
    

@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteChatClearAll(APIView):
    """
    Deletes all chat sessions (all logs) for a note.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, slug):
        note = get_object_or_404(Note.objects.select_related("user"), slug=slug)

        if not note.is_public and note.user_id != request.user.id:
            raise NotFound("Access denied.")

        deleted, _ = NoteChatLog.objects.filter(note=note).delete()
        if deleted == 0:
            return Response({"message": "No chat history found for this note."}, status=404)

        return Response({"message": f"Deleted all {deleted} chat messages for this note."}, status=200)