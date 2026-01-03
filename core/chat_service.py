import uuid
import json
import logging
from django.shortcuts import get_object_or_404
from apis.api_notes.models import Note, NoteChatLog
from .note_processor import ask_ai_with_note, count_tokens, summarize_chunks
from apis.api_auth.models import Wallet

logger = logging.getLogger(__name__)

def prepare_chat_context(request_user, slug, session_id, user_message):
    """Validate request and prepare note, wallet, chat history, etc."""
    note = get_object_or_404(Note, slug=slug)

    if not note.is_public and note.user != request_user:
        raise PermissionError("You cannot chat with this private note.")

    if not user_message:
        raise ValueError("Message is required.")

    # validate session_id
    try:
        session_id = uuid.UUID(str(session_id))
    except ValueError:
        raise ValueError("Invalid session_id")

    # prepare note content
    note_content = note.content or ""
    if len(note_content.split()) > 2000:
        note_content = summarize_chunks(note_content, max_chunk_size=2000)

    input_tokens = count_tokens(note_content) + count_tokens(user_message)
    estimated_output_tokens = 200
    total_tokens = input_tokens + estimated_output_tokens

    wallet, _ = Wallet.objects.get_or_create(user=request_user)

    if wallet.tokens < total_tokens:
        raise ValueError("Insufficient tokens in wallet")

    wallet.debit_tokens(total_tokens, description="token debit for chat with ai on note")

    # history
    chat_history = [
        {"user": c["user_message"], "ai": c["ai_response"]}
        for c in note.chat_logs.filter(session_id=session_id).values("user_message", "ai_response")
    ]

    return note, wallet, chat_history, note_content, session_id, total_tokens


def handle_ai_chat(note, user, session_id, user_message, note_content, wallet, chat_history):
    """
    Generator that yields {"delta": ...} and then {"done": True}.
    """
    ai_response_full = ""

    try:
        response_stream = ask_ai_with_note(
            note_content,
            user_message,
            max_chunk_size=1000,
            user_wallet=wallet,
            chat_history=chat_history,
            stream=True,
        )

        for chunk in response_stream:
            ai_response_full += chunk
            yield {"delta": chunk}

        # save once complete
        NoteChatLog.objects.create(
            note=note,
            user=user,
            session_id=session_id,
            user_message=user_message,
            ai_response=ai_response_full,
        )

        yield {"done": True}

    except Exception as e:
        logger.exception("AI chat failed")
        yield {"error": str(e)}
