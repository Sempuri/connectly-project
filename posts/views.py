from datetime import datetime
import json
import urllib.request as urllib_request
from django.db import connection  # For resetting ID sequences or direct database operations
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes  # For defining DRF API views
from rest_framework.views import APIView  # For defining DRF API views
from rest_framework.generics import RetrieveAPIView  # For defining DRF API views
from rest_framework import status, viewsets, permissions  # For HTTP status codes
from rest_framework.response import Response
from django.contrib.auth.models import Group  # Importing Django's User model for queries and serializers
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from .permissions import IsNotGuest, IsPostAuthor, IsAdmin
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers
from .models import User, Post, Comment, Like, Dislike  # Importing models for queries and serializers
from .serializers import PostSerializer, CommentSerializer, PostSerializer, UserSerializer, LikeSerializer, DislikeSerializer
from singletons.logger_singleton import LoggerSingleton
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from factories.post_factory import PostFactory
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.conf import settings
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView
from .utils import has_permission_to_manage_post, can_view_post, get_cache_key
from posts import models
from .jwt_serializers import CustomTokenObtainPairSerializer


# User Views
@api_view(['GET'])
@permission_classes([IsAdmin]) 
def get_users(request):
   try:
       users = User.objects.all()
       serializer = UserSerializer(users, many=True)  # Serialize multiple users
       return Response(serializer.data)
   except Exception as e:
       return Response({'error': str(e)}, status=500)
  
@api_view(['POST'])
@permission_classes([IsNotGuest]) 
def create_user(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email', '') # Optional email field
        # Get role from request, default to 'user'
        role = request.data.get('role', 'user')

         # Validate role
        if role not in [r[0] for r in User.ROLE_CHOICES]:
            return Response({'error': f'Invalid role. Choose from {[r[0] for r in User.ROLE_CHOICES]}'}, status=400)
        
        # Only admins can create other admins
        if role == 'admin' and (not request.user.is_authenticated or request.user.role != 'admin'):
            return Response({'error': 'Only admins can create admin users'}, status=403)


        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=400)
        
        try:
            if email:
                validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)

        user = User.objects.create_user(username=username, password=password, email=email, role=role)
        serializer = UserSerializer(user)
        return Response({'id': serializer.instance.id, 'message': 'User created successfully'}, status=201)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def authenticate_user(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=400)
        
        user = authenticate(username=username, password=password)
        if user is not None:
            return Response({'message': 'Authentication successful!'}, status=200)
        else:
            return Response({'error': 'Invalid credentials.'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def add_user_to_group(request):
    try:
        username = request.data.get('username')
        group_name = request.data.get('group_name')
        
        if not username or not group_name:
            return Response({'error': 'Username and group name are required'}, status=400)
        
        user = User.objects.get(username=username)
        group, created = Group.objects.get_or_create(name=group_name)
        user.groups.add(group)
        
        return Response({'message': f'User {username} added to group {group_name}'}, status=200)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def get_posts(request):
   try:
        user = request.user
        
        # Create a cache key for this user
        cache_key = get_cache_key('posts_list', user_id=user.id)
        
        # Try to get posts from cache
        cached_posts = cache.get(cache_key)
        if cached_posts is not None:
            return Response(cached_posts)
        
        # If not in cache, query the database
        posts = Post.objects.all().order_by('-created_at')
        
        # Serialize the data
        serializer = PostSerializer(posts, many=True)
        
        # Store in cache
        cache.set(cache_key, serializer.data, timeout=settings.CACHE_TTL.get('posts', 600))
        
        return Response(serializer.data)
   except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsNotGuest])
def create_post(request):
    try:
        content = request.data.get('content')
        privacy = request.data.get('privacy', 'public')  # Default to public
        
        if not content:
            return Response({'error': 'Content is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate privacy setting
        if privacy not in [p[0] for p in Post.PRIVACY_CHOICES]:
            return Response({'error': f'Invalid privacy setting. Choose from {[p[0] for p in Post.PRIVACY_CHOICES]}'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Create the post
        post = Post.objects.create(
            content=content,
            author=request.user,
            privacy=privacy
        )
        
        serializer = PostSerializer(post)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsNotGuest])
def edit_post(request, post_id):
    try:
        post = Post.objects.get(id=post_id)
        
        # Use the utility function to check permission
        if not has_permission_to_manage_post(request.user, post):
            return Response({'error': 'You do not have permission to edit this post.'}, 
                           status=status.HTTP_403_FORBIDDEN)
            
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            # Invalidate cache for this post and related feed caches
            cache_key = get_cache_key('post_detail', post_id=post_id, user_id=request.user.id)
            cache.delete(cache_key)
            
            # Invalidate all feed caches (safer approach for LocMemCache)
            try:
                # Try pattern-based deletion first (for Redis)
                if hasattr(cache, 'delete_pattern'):
                    cache.delete_pattern('feed_user_id_*')
                else:
                    # For LocMemCache, try to clear specific keys
                    # This is limited but works for development
                    cache_prefix = 'feed_user_id_'
                    # Clear cache for current user
                    cache.delete(f'{cache_prefix}{request.user.id}')
                    # If admin user exists with ID 1 (common in dev), clear that too
                    cache.delete(f'{cache_prefix}1')
            except Exception as cache_error:
                # Log the error but don't fail the request
                print(f"Cache invalidation error: {str(cache_error)}")
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsNotGuest])
def delete_post(request, post_id):
    try:
        post = Post.objects.get(id=post_id)
        
        # Use the utility function to check permission
        if not has_permission_to_manage_post(request.user, post):
            return Response({'error': 'You do not have permission to delete this post.'}, 
                           status=status.HTTP_403_FORBIDDEN)
            
        post.delete()
        return Response({'message': 'Post deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
@api_view(['DELETE'])
@permission_classes([IsAdmin])
def delete_user(request, user_id):
   try:
       user = User.objects.get(id=user_id)
       user.delete()
       return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
   except User.DoesNotExist:
       return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
   except Exception as e:
       return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  
@api_view(['POST'])
def reset_user_id(request):
   try:
       with connection.cursor() as cursor:
           cursor.execute("DELETE FROM sqlite_sequence WHERE name='yourapp_user';")
       return Response({'message': 'User ID sequence reset successfully'}, status=200)
   except Exception as e:
       return Response({'error': str(e)}, status=500)
  
class PostDetailView(RetrieveAPIView):
   queryset = Post.objects.all()
   serializer_class = PostSerializer


class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]


    def get(self, request, pk):
        post = Post.objects.get(pk=pk)
        self.check_object_permissions(request, post)
        return Response({"content": post.content})


class UserListCreate(APIView):
   permission_classes = [IsAdmin]  # Add this line to restrict to admins only
   def get(self, request):
        try:
            # Print debugging info
            print(f"User attempting to access user list: {request.user.username}, role: {request.user.role}")
            
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data)
        except Exception as e:
            print(f"Error in UserListCreate.get: {str(e)}")
            return Response(
                {"detail": "Error accessing user list", "error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

   def post(self, request):
       serializer = UserSerializer(data=request.data)
       if serializer.is_valid():
           serializer.save()
           return Response(serializer.data, status=status.HTTP_201_CREATED)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostListCreate(APIView):
   def get(self, request):
       posts = Post.objects.all()
       serializer = PostSerializer(posts, many=True)
       return Response(serializer.data)

   def post(self, request):
       serializer = PostSerializer(data=request.data)
       if serializer.is_valid():
           serializer.save()
           return Response(serializer.data, status=status.HTTP_201_CREATED)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CommentListCreate(APIView):
   def get(self, request):
       comments = Comment.objects.all()
       serializer = CommentSerializer(comments, many=True)
       return Response(serializer.data)

   def post(self, request):
       # First check if the post exists before validation
       post_id = request.data.get('post')
       if post_id and not Post.objects.filter(pk=post_id).exists():
           return Response(
               {"error": "Post not found"}, 
               status=status.HTTP_404_NOT_FOUND
           )
       
       serializer = CommentSerializer(data=request.data)
       if serializer.is_valid():
           serializer.save()
           return Response(serializer.data, status=status.HTTP_201_CREATED)
       
       # Check if this is a "Post not found" error
       if 'post' in serializer.errors and 'object does not exist' in str(serializer.errors['post']):
           return Response(
               {"error": "Post not found"}, 
               status=status.HTTP_404_NOT_FOUND
           )
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   
class LikeListCreate(APIView):
    def get(self, request):
        likes = Like.objects.all()
        serializer = LikeSerializer(likes, many=True)
        return Response(serializer.data)

    def post(self, request):
        # First check if the post exists before validation
        post_id = request.data.get('post')
        if post_id and not Post.objects.filter(pk=post_id).exists():
            return Response(
                {"error": "Post not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = LikeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Check if this is a duplicate like error from the unique_together constraint
        if 'non_field_errors' in serializer.errors and 'unique set' in str(serializer.errors['non_field_errors']):
            return Response(
                {"error": "You have already liked this post"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if this is a "Post not found" error
        if 'post' in serializer.errors and 'Post not found' in str(serializer.errors['post']):
            return Response(
                {"error": "Post not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class DislikeListCreate(APIView):
    def get(self, request):
        dislikes = Dislike.objects.all()
        serializer = DislikeSerializer(dislikes, many=True)
        return Response(serializer.data)

    def post(self, request):
        # First check if the post exists before validation
        post_id = request.data.get('post')
        if post_id and not Post.objects.filter(pk=post_id).exists():
            return Response(
                {"error": "Post not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if user has already liked this post
        author_id = request.data.get('author')
        if post_id and author_id and Like.objects.filter(post_id=post_id, author_id=author_id).exists():
            return Response(
                {"error": "You cannot dislike a post you have already liked. Remove your like first."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = DislikeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Check if this is a duplicate dislike error
        if 'non_field_errors' in serializer.errors and 'unique set' in str(serializer.errors['non_field_errors']):
            return Response(
                {"error": "You have already disliked this post"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if this is a "Post not found" error
        if 'post' in serializer.errors and ('object does not exist' in str(serializer.errors['post']) or 'Post not found' in str(serializer.errors['post'])):
            return Response(
                {"error": "Post not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def remove_like(request, post_id, author_id):
    try:
        try:
            post = Post.objects.get(pk=post_id)
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            author = User.objects.get(pk=author_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            like = Like.objects.get(post=post, author=author)
            like.delete()
            return Response({"message": "Like removed successfully"}, status=status.HTTP_200_OK)
        except Like.DoesNotExist:
            return Response({"error": "You have not liked this post"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
def remove_dislike(request, post_id, author_id):
    try:
        try:
            post = Post.objects.get(pk=post_id)
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            author = User.objects.get(pk=author_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            dislike = Dislike.objects.get(post=post, author=author)
            dislike.delete()
            return Response({"message": "Dislike removed successfully"}, status=status.HTTP_200_OK)
        except Dislike.DoesNotExist:
            return Response({"error": "You have not disliked this post"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
def remove_comment(request, comment_id):
    try:
        user = request.user
        comment = Comment.objects.get(pk=comment_id)
        
        # Check if user is admin, moderator, comment author, or post author
        if (user.role in ['admin', 'moderator'] or 
            comment.author == user or 
            comment.post.author == user):
            
            comment.delete()
            return Response({"message": "Comment removed successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You don't have permission to delete this comment"}, 
                           status=status.HTTP_403_FORBIDDEN)
            
    except Comment.DoesNotExist:
        return Response({"error": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
def remove_comment_by_ids(request, post_id, author_id, comment_id=None):
    try:
        try:
            post = Post.objects.get(pk=post_id)
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            author = User.objects.get(pk=author_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # If comment_id is provided, find that specific comment
        if comment_id:
            try:
                comment = Comment.objects.get(pk=comment_id, post=post, author=author)
                comment.delete()
                return Response({"message": "Comment removed successfully"}, status=status.HTTP_200_OK)
            except Comment.DoesNotExist:
                return Response({"error": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            # If no comment_id, find the most recent comment by this author on this post
            comments = Comment.objects.filter(post=post, author=author).order_by('-created_at')
            if not comments.exists():
                return Response({"error": "No comments found for this author on this post"}, 
                               status=status.HTTP_404_NOT_FOUND)
            
            # Delete the most recent comment
            comment = comments.first()
            comment.delete()
            return Response({"message": "Most recent comment removed successfully"}, 
                           status=status.HTTP_200_OK)
            
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


    def get(self, request):
        return Response({"message": "Authenticated!"})



logger = LoggerSingleton().get_logger()
logger.info("API initialized successfully.")


class FeedPagination(PageNumberPagination):
    page_size = 3
    page_size_query_param = 'page_size'  # Allow clients to override page size
    max_page_size = 100  # Set maximum allowed page size

class FeedView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PostSerializer
    pagination_class = FeedPagination

    def get_queryset(self):
        user = self.request.user
        page = self.request.query_params.get('page', 1)
        
        # Create a cache key specific to this user and page
        cache_key = get_cache_key('feed', user_id=user.id, page=page)
        
        # Try to get data from cache
        cached_posts = cache.get(cache_key)
        if cached_posts is not None:
            return cached_posts
        
        # If not in cache, query the database
        all_posts = Post.objects.select_related('author').all().order_by('-created_at')
        
        # Filter posts based on permission
        if self.request.user.role == 'admin':
            # Admins can see all posts
            visible_posts = all_posts
        else:
            # Regular users see public posts and their own private posts
            visible_posts = Post.objects.select_related('author').filter(
                models.Q(privacy='public') | 
                models.Q(privacy='private', author=self.request.user)
            ).order_by('-created_at')
        
        # Store in cache for future requests
        cache.set(cache_key, visible_posts, timeout=settings.CACHE_TTL.get('feed', 300))
        
        return visible_posts


@api_view(['PATCH'])
@permission_classes([IsAdmin])  # Only admins can update roles
def update_user_role(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        role = request.data.get('role')
        
        if not role:
            return Response({'error': 'Role is required'}, status=400)
        
        if role not in [r[0] for r in User.ROLE_CHOICES]:
            return Response({'error': f'Invalid role. Choose from {[r[0] for r in User.ROLE_CHOICES]}'}, status=400)
        
        user.role = role
        user.save()
        
        return Response({'message': f'User role updated to {role}'}, status=200)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_post_by_id(request, post_id):
    try:
        # Create a cache key for this post and user
        cache_key = get_cache_key('post_detail', post_id=post_id, user_id=request.user.id)
        
        # Try to get from cache
        cached_post = cache.get(cache_key)
        if cached_post is not None:
            return Response(cached_post)
        
        post = Post.objects.get(id=post_id)
        
        # Use the utility function to check permission
        if not can_view_post(request.user, post):
            return Response(
                {"error": "You don't have permission to view this private post"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = PostSerializer(post)
        
        # Cache the serialized data
        cache.set(cache_key, serializer.data, timeout=settings.CACHE_TTL.get('posts', 600))
        
        return Response(serializer.data)
    except Post.DoesNotExist:
        return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['GET'])
def test_api(request):
    return Response({
        "message": "API is working correctly", 
        "timestamp": datetime.now().isoformat()
    })

@api_view(['POST'])
def debug_auth(request):
    """Debug endpoint to test authentication directly"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({"error": "Username and password required"}, status=400)
    
    # Try direct authentication
    from django.contrib.auth import authenticate
    user = authenticate(request, username=username, password=password)
    
    if user:
        return Response({
            "success": True,
            "message": "Authentication successful",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        })
    
    # If authentication failed, determine why
    try:
        user = User.objects.get(username=username)
        from django.contrib.auth.hashers import check_password
        if check_password(password, user.password):
            return Response({"message": "Password is correct but authentication failed"})
        else:
            return Response({"error": "Password is incorrect"}, status=401)
    except User.DoesNotExist:
        return Response({"error": f"No user found with username: {username}"}, status=401)
    

class CustomTokenObtainPairView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CustomTokenObtainPairSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            return Response(serializer.validated_data)
        except Exception as e:
            return Response(
                {"detail": str(e), "code": "user_not_found" if "No user found" in str(e) else "authentication_failed"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )