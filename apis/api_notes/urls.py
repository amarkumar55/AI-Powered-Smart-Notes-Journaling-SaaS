from . import views
from django.urls import path



urlpatterns = [
    path("process_note/", views.NoteListCreate.as_view(), name="api.process_notes"),
    path("library/", views.UserNoteLibraryListCreateView.as_view(), name="user-library"),
    path("library/<slug:slug>/", views.UserNoteLibraryDeleteView.as_view(), name="user-library-delete"),
    path("<slug:slug>/", views.NoteDetail.as_view(), name="api.note_details"),
    path('<slug:slug>/like/', views.NoteLikeToggle.as_view(), name='note-like-toggle'),
    path('<slug:slug>/share/',views.NoteShare.as_view(), name='note-share'),
    path('<slug:slug>/comment/', views.NoteCommentCreate.as_view(), name='note-comment-create'),
    path('comment/<int:pk>/', views.NoteCommentDetail.as_view(), name='note-comment-detail'),
    path('<slug:slug>/comments/',views.NoteCommentList.as_view(), name='note-comment-list'),
    path("<slug:slug>/summarize/", views.NoteSummarizeView.as_view(), name="note-summarize"),
    path("<slug:slug>/chat/<uuid:session_id>/", views.NoteChatView.as_view(), name="note-chat"),
    path("<slug:slug>/chat/start/session/", views.NoteChatSession.as_view(), name="note-create-session"),
    path('<slug:slug>/chat/history/', views.NoteChatHistoryView.as_view(), name='note-chat-history'),
    path("<slug:slug>/chat/session/<uuid:session_id>/clear/", views.NoteChatClearSession.as_view(), name="note-chat-clear-session"),
    path("<slug:slug>/chat/clear-all/", views.NoteChatClearAll.as_view(), name="note-chat-clear-all"),
]