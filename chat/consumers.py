import json
from urllib.parse import parse_qs
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import User, Conversation, Message, Participant
from jwt import decode as jwt_decode, ExpiredSignatureError, InvalidTokenError
from django.conf import settings

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            query_string = self.scope['query_string'].decode()
            query_params = parse_qs(query_string)
            token = query_params.get('token', [None])[0]
            
            if not token:
                print("No token provided")
                await self.close(code=4001)
                return
            
            self.user = await self.get_user_from_token(token)
            
            if not self.user:
                print("Invalid token or user not found")
                await self.close(code=4002)
                return
            
            await self.accept()
            
            self.conversations = await self.get_user_conversations()
            
            await self.channel_layer.group_add(
                f"user_{self.user.id}",
                self.channel_name
            )
            
            for conv_id in self.conversations:
                group_name = f"conversation_{conv_id}"
                await self.channel_layer.group_add(
                    group_name,
                    self.channel_name
                )
                print(f"Added to conversation group: {group_name}")
            
            print(f"User {self.user.username} connected and joined {len(self.conversations)} conversations")
            
            await self.update_user_presence(True)
            
            await self.send(text_data=json.dumps({
                'type': 'connection_established',
                'user_id': self.user.id,
                'username': self.user.username,
                'message': 'Connected successfully'
            }))
            
        except Exception as e:
            print(f"WebSocket connection error: {str(e)}")
            await self.close(code=4000)

    async def disconnect(self, close_code):
        if hasattr(self, 'user'):
            if hasattr(self, 'conversations'):
                for conv_id in self.conversations:
                    group_name = f"conversation_{conv_id}"
                    await self.channel_layer.group_discard(
                        group_name,
                        self.channel_name
                    )
                    print(f"Left conversation group: {group_name}")
            
            if hasattr(self, 'group_name'):
                await self.channel_layer.group_discard(
                    self.group_name,
                    self.channel_name
                )
            
            await self.update_user_presence(False)
            print(f"User {self.user.username} disconnected")

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')
        
        if message_type == 'message':
            await self.handle_message(data)
        elif message_type == 'typing':
            await self.handle_typing(data)
        elif message_type == 'read_receipt':
            await self.handle_read_receipt(data)

    @database_sync_to_async
    def update_user_presence(self, is_online):
        User.objects.filter(id=self.user.id).update(
            status='online' if is_online else 'offline',
            last_seen_at=timezone.now()
        )

    async def handle_message(self, data):
        message = await self.save_message(data)
        
        await self.channel_layer.group_send(
            f"conversation_{data['conversation_id']}",
            {
                "type": "chat.message",
                "message": message
            }
        )

    @database_sync_to_async
    def save_message(self, data):
        conversation = Conversation.objects.get(id=data['conversation_id'])
        message = Message.objects.create(
            conversation=conversation,
            sender=self.user,
            type=data.get('message_type', 'text'),
            content=data['content']
        )
        return {
            'id': message.id,
            'sender_id': message.sender_id,
            'content': message.content,
            'created_at': message.created_at.isoformat()
        }

    async def chat_message(self, event):
        """
        Handle incoming chat messages
        """
        print(f"Received message for user {self.user.username}: {event}")
        await self.send(text_data=json.dumps(event))

    async def handle_typing(self, data):
        try:
            conversation_id = data['conversation_id']
            is_typing = data.get('is_typing', True)
            
            if conversation_id not in self.conversations:
                print(f"User {self.user.username} not in conversation {conversation_id}")
                return
            
            group_name = f"conversation_{conversation_id}"
            print(f"Sending typing notification to group: {group_name}")
            
            await self.channel_layer.group_send(
                group_name,
                {
                    "type": "typing_notification",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "conversation_id": conversation_id,
                    "is_typing": is_typing
                }
            )
            
        except Exception as e:
            print(f"Error handling typing notification: {str(e)}")

    async def typing_notification(self, event):
        """Handle typing notifications"""
        try:
            await self.send(text_data=json.dumps({
                'type': 'typing.notification',
                'user_id': event['user_id'],
                'username': event['username'],
                'conversation_id': event['conversation_id'],
                'is_typing': event['is_typing']
            }))
            print(f"Sent typing notification: User {event['username']} is {'typing' if event['is_typing'] else 'not typing'}")
        except Exception as e:
            print(f"Error sending typing notification: {str(e)}")

    async def handle_read_receipt(self, data):
        message_id = data['message_id']
        conversation_id = data['conversation_id']
        
        await self.update_read_receipt(message_id)
        
        await self.channel_layer.group_send(
            f"conversation_{conversation_id}",
            {
                "type": "read.receipt",
                "user_id": self.user.id,
                "message_id": message_id
            }
        )

    @database_sync_to_async
    def update_read_receipt(self, message_id):
        participant = Participant.objects.get(
            conversation__messages__id=message_id,
            user=self.user
        )
        participant.last_read_message_id = message_id
        participant.save()

    @database_sync_to_async
    def get_user_conversations(self):
        """Get all conversation IDs this user is part of"""
        return list(Participant.objects.filter(
            user=self.user,
            left_at__isnull=True 
        ).values_list('conversation_id', flat=True))

    @database_sync_to_async
    def get_user_from_token(self, token):
        try:
            decoded_data = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
            if decoded_data.get('token_type') != 'access':
                print("Invalid token type")
                return None
                
            user_id = decoded_data.get('user_id')
            if not user_id:
                print("No user_id in token")
                return None
                
            user = User.objects.get(id=user_id)
            print(f"Token validated for user {user.username}")
            return user
            
        except ExpiredSignatureError:
            print("Token has expired")
            return None
        except InvalidTokenError:
            print("Invalid token format")
            return None
        except User.DoesNotExist:
            print(f"User {user_id} not found")
            return None
        except Exception as e:
            print(f"Token validation error: {str(e)}")
            return None 