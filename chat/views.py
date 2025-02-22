from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework import status, permissions
from django.http import JsonResponse
from django.middleware.csrf import get_token
from drf_spectacular.utils import extend_schema, OpenApiExample
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from chat.serializers import RegisterSerializer, UserDetailSerializer


@method_decorator(csrf_exempt, name="dispatch")
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
                }
            )
        ]
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


class GetCSRFToken(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        response = JsonResponse({"details": "CSRF cookie set"})
        response["X-CSRFToken"] = get_token(request)
        return response
