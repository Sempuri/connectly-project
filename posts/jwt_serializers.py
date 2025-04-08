from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.auth.hashers import check_password

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'username'

    def validate(self, attrs):
        # Get username and password from request
        username = attrs.get('username')
        password = attrs.get('password')
        
        # Custom authentication against your User model
        try:
            user = User.objects.get(username=username)
            if check_password(password, user.password):
                # If authentication is successful, set self.user
                self.user = user
                
                # Get custom claims
                data = {}
                refresh = self.get_token(user)
                data['refresh'] = str(refresh)
                data['access'] = str(refresh.access_token)
                
                return data
            else:
                raise Exception("Invalid password")
        except User.DoesNotExist:
            raise Exception("No user found with this username")
    
    @classmethod
    def get_token(cls, user):
        """
        Create a custom token that works with your User model
        """
        token = RefreshToken()
        
        # Add custom claims
        token['user_id'] = user.id
        token['username'] = user.username
        token['role'] = user.role
        
        return token