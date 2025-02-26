from rest_framework import viewsets, permissions, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q, Count
from .models import User, Conversation, Message, Participant
from .serializers import (UserSerializer, ConversationSerializer, 
                        MessageSerializer, ParticipantSerializer,
                        RegisterSerializer, LoginSerializer, UserDetailSerializer,
                        CSRFTokenSerializer, LogoutResponseSerializer)
from django.contrib.auth import authenticate, login, logout
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .pagination import CustomPagination

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        queryset = User.objects.all().order_by('-last_seen_at')
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(username__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        return queryset

    @action(detail=False, methods=['GET'])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

class ConversationViewSet(viewsets.ModelViewSet):
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        queryset = Conversation.objects.filter(
            participants__user=self.request.user
        ).select_related(
            'last_message',
            'last_message__sender'
        ).prefetch_related(
            'participants',
            'participants__user'
        ).distinct()
        
        queryset = queryset.order_by(
            '-last_message__created_at',
            '-last_activity_at'
        )
        
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(participants__user__username__icontains=search)
            ).distinct()
        return queryset

    def perform_create(self, serializer):
        conversation = serializer.save(creator=self.request.user)
        Participant.objects.create(
            conversation=conversation,
            user=self.request.user,
            role='owner'
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'user_ids': {
                        'type': 'array',
                        'items': {'type': 'integer'},
                        'description': 'List of user IDs to add to the conversation'
                    },
                    'role': {
                        'type': 'string',
                        'enum': ['admin', 'moderator', 'member'],
                        'default': 'member',
                        'description': 'Role for the added participants'
                    }
                },
                'required': ['user_ids']
            }
        },
        responses={
            201: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'added_users': {'type': 'array', 'items': {'type': 'integer'}},
                    'failed_users': {
                        'type': 'object',
                        'properties': {
                            'user_id': {'type': 'string'}
                        }
                    }
                }
            }
        },
        description='Add multiple participants to the conversation'
    )
    @action(detail=True, methods=['POST'], url_path='add-participants')
    def add_participants(self, request, pk=None):
        conversation = self.get_object()
        user_ids = request.data.get('user_ids', [])
        role = request.data.get('role', 'member')
        
        if not user_ids:
            return Response(
                {'error': 'No user IDs provided'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        added_users = []
        failed_users = {}

        for user_id in user_ids:
            try:
                user = User.objects.get(id=user_id)
                
                if Participant.objects.filter(conversation=conversation, user=user).exists():
                    failed_users[user_id] = 'Already a participant'
                    continue

                Participant.objects.create(
                    conversation=conversation,
                    user=user,
                    role=role
                )
                added_users.append(user_id)

            except User.DoesNotExist:
                failed_users[user_id] = 'User not found'
            except Exception as e:
                failed_users[user_id] = str(e)

        response_data = {
            'message': f'Added {len(added_users)} participants',
            'added_users': added_users
        }
        
        if failed_users:
            response_data['failed_users'] = failed_users

        return Response(
            response_data,
            status=status.HTTP_201_CREATED if added_users else status.HTTP_400_BAD_REQUEST
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        responses={200: ConversationSerializer(many=True)},
        description='List all conversations for the current user'
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
        request=ConversationSerializer,
        responses={201: ConversationSerializer},
        description='Create a new conversation'
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            ),
            OpenApiParameter(
                name='user_id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description='User ID to add to the conversation (can be provided in query or body)'
            )
        ],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'user_id': {
                        'type': 'integer',
                        'description': 'User ID to add to the conversation'
                    },
                    'role': {
                        'type': 'string',
                        'enum': ['admin', 'moderator', 'member'],
                        'default': 'member'
                    }
                }
            }
        },
        responses={
            201: {'type': 'object', 'properties': {'message': {'type': 'string'}}},
            400: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
            404: {'type': 'object', 'properties': {'error': {'type': 'string'}}}
        },
        description='Add a single participant to the conversation'
    )
    @action(detail=True, methods=['POST'], url_path='add-participant')
    def add_participant(self, request, pk=None):
        conversation = self.get_object()
        
        user_id = request.query_params.get('user_id') or request.data.get('user_id')
        role = request.data.get('role', 'member')
        
        if not user_id:
            return Response(
                {'error': 'user_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user_id = int(user_id)
            user = User.objects.get(id=user_id)
            
            if Participant.objects.filter(conversation=conversation, user=user).exists():
                return Response(
                    {'error': 'User is already a participant'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            Participant.objects.create(
                conversation=conversation,
                user=user,
                role=role
            )
            return Response(
                {'message': f'User {user.username} added successfully'},
                status=status.HTTP_201_CREATED
            )
        except ValueError:
            return Response(
                {'error': 'Invalid user_id format'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        responses={200: ConversationSerializer},
        description='Retrieve a specific conversation'
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        request=ConversationSerializer,
        responses={200: ConversationSerializer},
        description='Update a conversation'
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        request=ConversationSerializer,
        responses={200: ConversationSerializer},
        description='Partially update a conversation'
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='id',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Conversation ID'
            )
        ],
        responses={204: None},
        description='Delete a conversation'
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='user1',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description='First participant ID'
            ),
            OpenApiParameter(
                name='user2',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description='Second participant ID'
            )
        ],
        responses={
            200: ConversationSerializer,
            404: {'type': 'object', 'properties': {'message': {'type': 'string'}}}
        },
        description='Find direct conversation between two users'
    )
    @action(detail=False, methods=['GET'], url_path='find-direct')
    def find_direct_conversation(self, request):
        user1_id = request.query_params.get('user1')
        user2_id = request.query_params.get('user2')
        
        if not user1_id or not user2_id:
            return Response(
                {'message': 'Both user IDs are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            conversation = Conversation.objects.filter(
                type='direct'
            ).annotate(
                participant_count=Count('participants')
            ).filter(
                participant_count=2,
                participants__user_id__in=[user1_id, user2_id]
            ).filter(
                participants__user_id__in=[user1_id, user2_id]
            ).distinct()
            
            if conversation.exists():
                serializer = self.get_serializer(conversation.first())
                return Response(serializer.data)
            else:
                return Response(
                    {'message': f'No direct conversation found between users {user1_id} and {user2_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as e:
            return Response(
                {'message': f'Error finding conversation: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

class MessageViewSet(viewsets.ModelViewSet):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'

    def get_queryset(self):
        conversation_id = self.request.query_params.get('conversation')
        queryset = Message.objects.filter(
            conversation__participants__user=self.request.user
        )
        if conversation_id:
            queryset = queryset.filter(conversation_id=conversation_id)
            
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(content__icontains=search) |
                Q(sender__username__icontains=search)
            )
            
        return queryset.order_by('-created_at')

    def perform_create(self, serializer):
        message = serializer.save(sender=self.request.user)
        
        conversation = message.conversation
        conversation.last_message = message
        conversation.last_activity_at = message.created_at
        conversation.save()
        
        channel_layer = get_channel_layer()
        
        message_data = {
            'type': 'chat.message',
            'message': {
                'id': message.id,
                'conversation_id': message.conversation.id,
                'sender': {
                    'id': message.sender.id,
                    'username': message.sender.username,
                    'avatar_url': message.sender.avatar_url
                },
                'content': message.content,
                'type': message.type,
                'reply_to': message.reply_to.id if message.reply_to else None,
                'metadata': message.metadata,
                'reactions': message.reactions,
                'created_at': message.created_at.isoformat()
            }
        }

        for participant in message.conversation.participants.all():
            if participant.user_id != self.request.user.id:
                async_to_sync(channel_layer.group_send)(
                    f"user_{participant.user_id}",
                    message_data
                )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='conversation',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description='Filter messages by conversation ID'
            )
        ],
        responses={200: MessageSerializer(many=True)},
        description='List messages, optionally filtered by conversation'
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
        request=MessageSerializer,
        responses={201: MessageSerializer},
        description='Send a new message'
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                required=True,
                description='Message ID'
            )
        ],
        responses={200: MessageSerializer},
        description='Retrieve a specific message'
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Message ID'
            )
        ],
        request=MessageSerializer,
        responses={200: MessageSerializer},
        description='Update a message'
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Message ID'
            )
        ],
        request=MessageSerializer,
        responses={200: MessageSerializer},
        description='Partially update a message'
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Message ID'
            )
        ],
        responses={204: None},
        description='Delete a message'
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='pk',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.PATH,
                description='Message ID'
            )
        ],
        responses={200: None},
        description='Mark message as read'
    )
    @action(detail=True, methods=['POST'])
    def mark_read(self, request, pk=None):
        message = self.get_object()
        participant = Participant.objects.get(
            conversation=message.conversation,
            user=request.user
        )
        participant.last_read_message = message
        participant.save()
        return Response(status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        request=RegisterSerializer,
        responses={201: UserDetailSerializer},
        description='Register a new user account',
        examples=[
            OpenApiExample(
                'Valid Registration',
                value={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': 'securepass123',
                    'confirm_password': 'securepass123',
                    'first_name': 'Test',
                    'last_name': 'User',
                    'phone': '+1234567890',
                    'avatar_url': 'https://example.com/avatar.jpg',
                    'settings': {
                        'notifications': True,
                        'theme': 'dark'
                    }
                }
            )
        ]
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            return Response({
                'user': UserDetailSerializer(user).data,
                'message': 'Registration successful'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        request=LoginSerializer,
        responses={200: LoginSerializer},
        description='Login with username/email and password'
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            request.user.status = 'offline'
            request.user.last_seen_at = timezone.now()
            request.user.save()
            
            return Response({"message": "Successfully logged out"})
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: UserDetailSerializer},
        description='Get current user profile'
    )
    def get(self, request):
        """Get user's own profile"""
        serializer = UserDetailSerializer(request.user)
        return Response(serializer.data)
    
    @extend_schema(
        request=UserDetailSerializer,
        responses={200: UserDetailSerializer},
        description='Update current user profile'
    )
    def patch(self, request):
        """Update user's own profile"""
        serializer = UserDetailSerializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 