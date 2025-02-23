from rest_framework import serializers
from .models import User, Participant, Message, Conversation
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
            "confirm_password",
            "first_name",
            "last_name",
            "phone",
            "avatar_url",
            "status",
            "settings",
        ]
        extra_kwargs = {
            "email": {"required": True},
            "phone": {"required": False},
            "avatar_url": {"required": False},
            "status": {"read_only": True},
            "settings": {"required": False},
        }

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")

        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is already in use.")

        phone = data.get("phone")
        if phone and User.objects.filter(phone=phone).exists():
            raise serializers.ValidationError("Phone is already in use.")

        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password", None)

        validated_data["status"] = "offline"
        validated_data["is_verified"] = False
        validated_data["settings"] = validated_data.get(
            "settings",
            {
                "notifications": True,
                "sound": True,
                "email_notifications": True,
                "language": "en",
                "theme": "light",
            },
        )

        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            phone=validated_data.get("phone", ""),
            avatar_url=validated_data.get("avatar_url", ""),
            status="offline",
            settings=validated_data["settings"],
        )
        return user


class UserDetailSerializer(serializers.ModelSerializer):
    """Detailed user serializer for profile view"""

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "phone",
            "avatar_url",
            "status",
            "last_seen_at",
            "is_verified",
            "is_active",
            "is_blocked",
            "settings",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "is_verified",
            "last_seen_at",
            "created_at",
            "updated_at",
        ]


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data["user"] = UserDetailSerializer(self.user).data
        return data


class LoginSerializer(MyTokenObtainPairSerializer):
    username_or_email = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("username", None)

    def validate(self, attrs):
        username_or_email = attrs.get("username_or_email")
        password = attrs.get("password")

        if "@" in username_or_email:
            user = User.objects.filter(email=username_or_email).first()
            if user:
                username = user.username
            else:
                raise serializers.ValidationError(
                    {"username_or_email", "User not found"}
                )
        else:
            username = username_or_email
            if not User.objects.filter(username=username).exists():
                raise serializers.ValidationError(
                    {"username_or_email": "User not found"}
                )

        validated_attrs = {"username": username, "password": password}

        return super().validate(validated_attrs)

    class Meta:
        fields = ("username_or_email", "password")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "avatar_url",
            "status",
            "last_seen_at",
            "is_verified",
        ]


class ParticipantSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Participant
        fields = [
            "id",
            "conversation",
            "user",
            "role",
            "nickname",
            "last_read_message",
            "is_muted",
            "joined_at",
        ]


class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation",
            "sender",
            "reply_to",
            "type",
            "content",
            "metadata",
            "is_edited",
            "delivered_at",
            "read_by",
            "reactions",
            "created_at",
        ]
        read_only_fields = ["sender", "delivered_at", "read_by"]

class ConversationSerializer(serializers.ModelSerializer):
    participants = ParticipantSerializer(many=True, read_only=True)
    last_message = MessageSerializer(read_only=True)

    class Meta:
        model = Conversation
        fields = [
            "id",
            "type",
            "title",
            "description",
            "avatar_url",
            "creator",
            "participants",
            "last_message",
            "last_activity_at",
            "created_at",
        ]
