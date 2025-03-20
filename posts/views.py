import json
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
from .permissions import IsPostAuthor
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
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView


# User Views
@api_view(['GET'])
def get_users(request):
   try:
       users = User.objects.all()
       serializer = UserSerializer(users, many=True)  # Serialize multiple users
       return Response(serializer.data)
   except Exception as e:
       return Response({'error': str(e)}, status=500)
  
@api_view(['POST'])
def create_user(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email', '') # Optional email field
        
        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=400)
        
        try:
            if email:
                validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)

        user = User.objects.create_user(username=username, password=password, email=email)
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
       posts = Post.objects.all()
       serializer = PostSerializer(posts, many=True)
       return Response(serializer.data)
   except Exception as e:
       return Response({'error': str(e)}, status=500)


@api_view(['POST'])
def create_post(request):
   if request.method == 'POST':
    try:
        data = json.loads(request.body)
        author = User.objects.get(id=data['author'])
        post = Post.objects.create(content=data['content'], author=author)
        return JsonResponse({'id': post.id, 'message': 'Post created successfully'}, status=201)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Author not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def edit_post(request, post_id):
    try:
        user = request.user
        if not user.groups.filter(name='Admin').exists():
            return Response({'error': 'You do not have permission to edit this post.'}, status=status.HTTP_403_FORBIDDEN)
        
        post = Post.objects.get(id=post_id)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_post(request, post_id):
    try:
        user = request.user
        if not user.groups.filter(name='Admin').exists():
            return Response({'error': 'You do not have permission to delete this post.'}, status=status.HTTP_403_FORBIDDEN)
        
        post = Post.objects.get(id=post_id)
        post.delete()
        return Response({'message': 'Post deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
@api_view(['DELETE'])
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
   def get(self, request):
       users = User.objects.all()
       serializer = UserSerializer(users, many=True)
       return Response(serializer.data)

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
        try:
            comment = Comment.objects.get(pk=comment_id)
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)
        
        comment.delete()
        return Response({"message": "Comment removed successfully"}, status=status.HTTP_200_OK)
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

class FeedView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PostSerializer
    pagination_class = FeedPagination

    def get_queryset(self):
        # Retrieve posts sorted by newest first
        return Post.objects.all().order_by('-created_at')
