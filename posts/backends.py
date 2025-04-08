from django.contrib.auth.hashers import check_password
from .models import User

class CustomUserBackend:
    def authenticate(self, request=None, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username=username)
            if check_password(password, user.password):
                return user
            return None
        except User.DoesNotExist:
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None