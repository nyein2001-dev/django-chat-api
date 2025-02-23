from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework import status, permissions
from django.http import JsonResponse
from django.middleware.csrf import get_token
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiTypes
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
import logging

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


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Logout user",
        description="Logs out the authenticated user by blacklisting the refresh token and updating user status.",
        request=OpenApiTypes.OBJECT,
        responses={200: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT},
        examples=[
            OpenApiExample(
                "Successful Logout",
                description="User logs out successfully.",
                value={"message": "Successfully logged out"},
                response_only=True,
                status_codes=["200"],
            ),
            OpenApiExample(
                "Invalid Request",
                description="Invalid or missing refresh token.",
                value={"detail": "Invalid token"},
                response_only=True,
                status_codes=["400"],
            ),
        ],
    )
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            request.user.status = "offline"
            request.user.last_seen_at = timezone.now()
            request.user.save()

            return Response({"message": "Successfully logged out"})
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)
