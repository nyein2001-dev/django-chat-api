from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework import status, permissions
from django.http import JsonResponse
from django.middleware.csrf import get_token
from drf_spectacular.utils import extend_schema, OpenApiExample
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone

from chat.serializers import RegisterSerializer, UserDetailSerializer, LoginSerializer


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=RegisterSerializer,
        responses={201: UserDetailSerializer},
        description="Register a new user account",
        examples=[
            OpenApiExample(
                "Valid Registration",
                value={
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "securepass123",
                    "confirm_password": "securepass123",
                    "first_name": "Test",
                    "last_name": "User",
                    "phone": "+1234567890",
                    "avatar_url": "https://example.com/avatar.jpg",
                    "settings": {"notifications": True, "theme": "dark"},
                },
            )
        ],
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            return Response(
                {
                    "user": UserDetailSerializer(user).data,
                    "message": "User registered successfully",
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={200: LoginSerializer},
        description="Login with username/email and password",
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError as e:
                logger.warning(f"Token blacklist failed: {str(e)}")
                return Response(
                    {"error": "Invalid or expired refresh token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                request.user.status = "offline"
                request.user.last_seen_at = timezone.now()
                request.user.save()
            except Exception as e:
                logger.error(f"Failed to update user status: {str(e)}")
                return Response(
                    {
                        "message": "Logged out successfully",
                        "warning": "Failed to update user status",
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"message": "Successfully logged out"}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during logout"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
