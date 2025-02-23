from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework import status, permissions
from drf_spectacular.utils import (
    extend_schema,
    OpenApiExample,
    OpenApiTypes,
    OpenApiParameter,
)
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from rest_framework import viewsets
from .models import User, Conversation, Participant
from rest_framework.decorators import action

from chat.serializers import (
    RegisterSerializer,
    UserDetailSerializer,
    LoginSerializer,
    UserSerializer,
    ConversationSerializer,
)


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


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["GET"])
    def me(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class ConversationViewSet(viewsets.ModelViewSet):
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Conversation.objects.filter(
            participants__user=self.request.user
        ).distinct()

    def perform_create(self, serializer):
        conversation = serializer.save(creator=self.request.user)
        Participant.objects.create(
            conversation=conversation, user=self.request.user, role="owner"
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="pk",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "user_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of user IDs to add to the conversation",
                    },
                    "role": {
                        "type": "string",
                        "enum": ["admin", "moderator", "member"],
                        "default": "member",
                        "description": "Role for the added participants",
                    },
                },
                "required": ["user_ids"],
            }
        },
        responses={
            201: {
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "added_users": {"type": "array", "items": {"type": "integer"}},
                    "failed_users": {
                        "type": "object",
                        "properties": {"user_id": {"type": "string"}},
                    },
                },
            }
        },
        description="Add multiple participants to the conversation",
    )
    @action(detail=True, methods=["POST"], url_path="add-participants")
    def add_participants(self, request, pk=None):
        conversation = self.get_object()
        user_ids = request.data.get("user_ids", [])
        role = request.data.get("role", "member")

        if not user_ids:
            return Response(
                {"error": "No user IDs provided"}, status=status.HTTP_400_BAD_REQUEST
            )

        added_users = []
        failed_users = {}

        for user_id in user_ids:
            try:
                user = User.objects.get(id=user_id)

                if Participant.objects.filter(
                    conversation=conversation, user=user
                ).exists():
                    failed_users[user_id] = "Already a participant"
                    continue

                Participant.objects.create(
                    conversation=conversation, user=user, role=role
                )
                added_users.append(user_id)

            except User.DoesNotExist:
                failed_users[user_id] = "User not found"
            except Exception as e:
                failed_users[user_id] = str(e)

        response_data = {
            "message": f"Added {len(added_users)} participants",
            "added_users": added_users,
        }

        if failed_users:
            response_data["failed_users"] = failed_users

        return Response(
            response_data,
            status=(
                status.HTTP_201_CREATED if added_users else status.HTTP_400_BAD_REQUEST
            ),
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        responses={200: ConversationSerializer(many=True)},
        description="List all conversations for the current user",
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
        request=ConversationSerializer,
        responses={201: ConversationSerializer},
        description="Create a new conversation",
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="pk",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            ),
            OpenApiParameter(
                name="user_id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="User ID to add to the conversation (can be provided in query or body)",
            ),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "integer",
                        "description": "User ID to add to the conversation",
                    },
                    "role": {
                        "type": "string",
                        "enum": ["admin", "moderator", "member"],
                        "default": "member",
                    },
                },
            }
        },
        responses={
            201: {"type": "object", "properties": {"message": {"type": "string"}}},
            400: {"type": "object", "properties": {"error": {"type": "string"}}},
            404: {"type": "object", "properties": {"error": {"type": "string"}}},
        },
        description="Add a single participant to the conversation",
    )
    @action(detail=True, methods=["POST"], url_path="add-participant")
    def add_participant(self, request, pk=None):
        conversation = self.get_object()

        user_id = request.query_params.get("user_id") or request.data.get("user_id")
        role = request.data.get("role", "member")

        if not user_id:
            return Response(
                {"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user_id = int(user_id)
            user = User.objects.get(id=user_id)

            if Participant.objects.filter(
                conversation=conversation, user=user
            ).exists():
                return Response(
                    {"error": "User is already a participant"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            Participant.objects.create(conversation=conversation, user=user, role=role)
            return Response(
                {"message": f"User {user.username} added successfully"},
                status=status.HTTP_201_CREATED,
            )
        except ValueError:
            return Response(
                {"error": "Invalid user_id format"}, status=status.HTTP_400_BAD_REQUEST
            )
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        responses={200: ConversationSerializer},
        description="Retrieve a specific conversation",
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        request=ConversationSerializer,
        responses={200: ConversationSerializer},
        description="Update a conversation",
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        request=ConversationSerializer,
        responses={200: ConversationSerializer},
        description="Partially update a conversation",
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description="Conversation ID",
            )
        ],
        responses={204: None},
        description="Delete a conversation",
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
