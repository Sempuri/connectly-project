from django.urls import path
from . import views
from rest_framework.authtoken.views import obtain_auth_token
from .views import authenticate_user, UserListCreate, PostListCreate, CommentListCreate, LikeListCreate, DislikeListCreate, remove_like, remove_dislike, remove_comment, remove_comment_by_ids, add_user_to_group, edit_post, delete_post, FeedView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.contrib import admin




urlpatterns = [

   path('users/', views.get_users, name='get_users'),
   path('users/create/', views.create_user, name='create_user'),
   path('users/<int:user_id>/role/', views.update_user_role, name='update_user_role'),
   path('authenticate_user/', authenticate_user, name='authenticate_user'),
   path('users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
   path('users/reset-id/', views.reset_user_id, name='reset_user_id'),
   path('add_user_to_group/', add_user_to_group, name='add_user_to_group'),
   path('posts/', views.get_posts, name='get_posts'),
   path('posts/<int:post_id>/', views.get_post_by_id, name='get_post_by_id'),
   path('posts/create/', views.create_post, name='create_post'),
   path('posts/edit/<int:post_id>/', edit_post, name='edit_post'),
   path('posts/delete/<int:post_id>/', delete_post, name='delete_post'),
   path('users/api/', UserListCreate.as_view(), name='user-list-create'),
   path('posts/', PostListCreate.as_view(), name='post-list-create'),
   path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
   path('likes/', LikeListCreate.as_view(), name='like-list-create'),
   path('dislikes/', DislikeListCreate.as_view(), name='dislike-list-create'),
   path('likes/remove/<int:post_id>/<int:author_id>/', remove_like, name='remove-like'),
   path('dislikes/remove/<int:post_id>/<int:author_id>/', remove_dislike, name='remove-dislike'),
   # For removing a specific comment by ID
   path('comments/remove/<int:comment_id>/', remove_comment, name='remove-comment'),
   # For removing comments by post and author IDs
   path('comments/remove/<int:post_id>/<int:author_id>/', remove_comment_by_ids, name='remove-comment-by-ids'),
   # For removing a specific comment with all IDs
   path('comments/remove/<int:post_id>/<int:author_id>/<int:comment_id>/', remove_comment_by_ids, name='remove-specific-comment'),
   
   path('feed/', FeedView.as_view(), name='feed'),
   path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
   path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   path('test/', views.test_api, name='test-api'),
   path('debug/auth/', views.debug_auth, name='debug-auth'),
]
