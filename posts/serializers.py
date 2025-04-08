from rest_framework import serializers
from posts.models import Comment, Post, User, Like, Dislike  # For creating serializers


class UserSerializer(serializers.ModelSerializer):
   
   class Meta:
       model = User
       fields = ['id', 'username', 'email', 'created_at', 'role']


       def validate_username(self, value):
           if User.objects.filter(username=value).exists():
               raise serializers.ValidationError("User not found.")
           return value
      
class PostSerializer(serializers.ModelSerializer):
   comments = serializers.StringRelatedField(many=True, read_only=True)  # Nested serializer for comments
   likes = serializers.StringRelatedField(many=True, read_only=True)  # Nested serializer for likes
   dislikes = serializers.StringRelatedField(many=True, read_only=True)

   class Meta:
       model = Post
       fields = ['id', 'content', 'author', 'created_at', 'privacy', 'comments', 'likes', 'dislikes']

   def validate_author(self, value):
       if not User.objects.filter(id=value.id).exists():
           raise serializers.ValidationError("Author not found.")
       return value

class CommentSerializer(serializers.ModelSerializer):
   class Meta:
       model = Comment
       fields = ['id', 'author', 'post', 'text', 'created_at']


   def validate_post(self, value):
        try:
            post = Post.objects.get(pk=value.pk)
            return post
        except Post.DoesNotExist:
            raise serializers.ValidationError("Post not found.")


   def validate_author(self, value):
       if not User.objects.filter(id=value.id).exists():
           raise serializers.ValidationError("Author not found.")
       return value
   
class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = ['id','author', 'post', 'created_at']

    def validate_post(self, value):
        try:
            post = Post.objects.get(pk=value.pk)
            return post
        except Post.DoesNotExist:
            raise serializers.ValidationError("Post not found.")

    def validate(self, data):
        # Check if this user has already liked this post
        author = data.get('author')
        post = data.get('post')
        
        if Like.objects.filter(author=author, post=post).exists():
            raise serializers.ValidationError("You have already liked this post.")
        
        return data

    def validate_post(self, value):
       if not Post.objects.filter(id=value.id).exists():
           raise serializers.ValidationError("Post not found.")
       return value


    def validate_author(self, value):
       if not User.objects.filter(id=value.id).exists():
           raise serializers.ValidationError("Author not found.")
       return value

class DislikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dislike
        fields = ['id', 'author', 'post', 'created_at']

    def validate_post(self, value):
        try:
            post = Post.objects.get(pk=value.pk)
            return post
        except Post.DoesNotExist:
            raise serializers.ValidationError("Post not found.")
    
    def validate(self, data):
        # Check if user has already liked the post
        author = data.get('author')
        post = data.get('post')
        
        if Like.objects.filter(author=author, post=post).exists():
            raise serializers.ValidationError("You cannot dislike a post you have already liked. Remove your like first.")
        
        if Dislike.objects.filter(author=author, post=post).exists():
            raise serializers.ValidationError("You have already disliked this post.")
        
        return data

    def validate_author(self, value):
        if not User.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Author not found.")
        return value