# File: api/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

# For handling expired token sessions
from django.utils import timezone
from datetime import timedelta
from rest_framework.authtoken.models import Token
from django.contrib.auth import logout

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_resource(request):
    """
    A simple protected resource that requires authentication.
    Will return 401 Unauthorized if invalid or missing token.
    """
    return Response({
        "message": "You have access to this protected resource",
        "user": request.user.username,
        "email": request.user.email
    })

""""""
@api_view(['POST'])
def create_expiring_token(request):
    """
    Creates a token that will expire in the specified number of seconds.
    For testing purposes only.
    """
    if not request.user.is_authenticated:
        return Response({"error": "You must be logged in"}, status=status.HTTP_401_UNAUTHORIZED)
        
    # Delete any existing tokens for this user
    Token.objects.filter(user=request.user).delete()
    
    # Create a new token
    token = Token.objects.create(user=request.user)
    
    # Get expiry time from request (default: 30 seconds)
    expiry_seconds = int(request.data.get('expiry_seconds', 30))
    
    # Store the expiry time in a way that's accessible to the expiry checker
    # Note: This is a simplified implementation for testing
    expiry_time = timezone.now() + timedelta(seconds=expiry_seconds)
    
    # Store expiry as a custom property on the token object
    # This would typically be done in a custom Token model, but we're keeping it simple
    setattr(token, 'expires_at', expiry_time)
    
    return Response({
        "token": token.key,
        "expires_at": expiry_time.isoformat(),
        "valid_for_seconds": expiry_seconds,
        "testing_instructions": "Use this token in the Authorization header like: 'Token YOUR_TOKEN_HERE'"
    })

@api_view(['GET'])
def check_token_expired(request):
    """
    Endpoint to check if a token is expired.
    This is a simple simulation for testing.
    For proper implementation, use a custom token model with expiry.
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    
    if not auth_header.startswith('Token '):
        return Response({
            "error": "Invalid authentication. Use 'Token YOUR_TOKEN_HERE' format."
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    token_key = auth_header.split(' ')[1]
    
    try:
        token = Token.objects.get(key=token_key)
        
        # Check if token has an expiry time set
        if hasattr(token, 'expires_at'):
            # Check if token is expired
            if token.expires_at < timezone.now():
                return Response({
                    "error": "Token has expired",
                    "expired_at": token.expires_at.isoformat()
                }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            "message": "Token is valid",
            "user": token.user.username
        })
    
    except Token.DoesNotExist:
        return Response({
            "error": "Invalid token"
        }, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def expire_session(request):
    """
    Forcefully expires the current session for testing purposes.
    """
    if not request.user.is_authenticated:
        return Response({"error": "No active session"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Get the current session key before logout
    session_key = request.session.session_key
    
    # Log the user out - this will invalidate the session
    logout(request)
    
    return Response({
        "message": "Session has been expired",
        "expired_session_id": session_key,
        "testing_instructions": "Your session has been invalidated. Try accessing protected resources with this session."
    }) 
""""""