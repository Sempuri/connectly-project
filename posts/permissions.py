from rest_framework.permissions import BasePermission


class IsPostAuthor(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            getattr(request.user, 'role', None) == 'admin'
        )

class IsNotGuest(BasePermission):
    """Permission class to restrict guests from performing actions"""
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and 
            getattr(request.user, 'role', None) != 'guest'
        )
    
class CanViewPost(BasePermission):
    """
    Permission to check if a user can view a post based on privacy settings.
    """
    def has_object_permission(self, request, view, obj):
        # Public posts can be viewed by anyone
        if obj.privacy == 'public':
            return True
            
        # Private posts can only be viewed by the author or admins
        return obj.author == request.user or getattr(request.user, 'role', None) == 'admin'