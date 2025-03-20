from django.db import models
from django.forms import ValidationError
from django.contrib.auth.hashers import make_password

class UserManager(models.Manager):
    def create_user(self, username, password, email=None, **extra_fields):
        if not username:
            raise ValueError('The Username field is required')
        
        email = email or ''
            
        user = self.model(username=username, email=email, **extra_fields)
        user.password = make_password(password)  # Hash the password
        user.save(using=self._db)
        return user

class User(models.Model):
   username = models.CharField(max_length=100, unique=True) # User's unique username
   email = models.EmailField(unique=True) # User's unique email
   password = models.CharField(max_length=128)  # Make sure password field exists
   created_at = models.DateTimeField(auto_now_add=True) # Timestamp when the user was created

   # Add this line to connect your manager to the model
   objects = UserManager()

   def __str__(self):
       return self.username


class Post(models.Model):
   content = models.TextField() # The text content of the post
   author = models.ForeignKey(User, on_delete=models.CASCADE) # The user who created the post
   created_at = models.DateTimeField(auto_now_add=True) # Timestamp when the post was created


   def __str__(self):
       return self.content[:50]
  

class Comment(models.Model):
   text = models.TextField()
   author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
   post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
   created_at = models.DateTimeField(auto_now_add=True)


   def __str__(self):
       return f"Commented by {self.author.username} on Post."


class Like(models.Model):
    post = models.ForeignKey(Post, related_name='likes', on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='likes', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        # to ensure a user can only like a post once
        unique_together = ['post', 'author']
    
    def __str__(self):
        return f"Liked by {self.author.username} on Post."
    

class Dislike(models.Model):
    post = models.ForeignKey(Post, related_name='dislikes', on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='dislikes', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        # to ensure a user can only dislike a post once
        unique_together = ['post', 'author']
    
    def __str__(self):
        return f"Disliked by {self.author.username} on Post."