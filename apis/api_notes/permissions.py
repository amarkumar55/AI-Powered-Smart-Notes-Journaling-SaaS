
from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsOwnerOrReadOnly(BasePermission):
    """
    Allow access if:
    - The note is public (anyone can view, read-only).
    - The note is private (only the owner can view).
    """

    def has_object_permission(self, request, view, obj):
        # ✅ Anyone can view public notes (read-only methods only)
        if obj.is_public and request.method in SAFE_METHODS:
            return True

        # ✅ Only owner can access private notes
        return obj.user == request.user

