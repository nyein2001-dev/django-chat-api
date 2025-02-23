from rest_framework import serializers
from .models import User


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
            'email': {'required': True},
            'phone': {'required': False},
            'avatar_url': {'required': False},
            'status': {'read_only': True},
            'settings': {'required': False}
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
