from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    phone = models.CharField(max_length=16, unique=True, null=True)
    avatar_url = models.CharField(max_length=255, null=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ("online", "Online"),
            ("offline", "Offline"),
            ("busy", "Busy"),
            ("away", "Away"),
            ("invisible", "Invisible"),
        ],
        default="offline",
    )
    last_seen_at = models.DateTimeField(null=True)
    is_verified = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    settings = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users"


class Conversation(models.Model):
    type = models.CharField(
        max_length=20,
        choices=[
            ("direct", "Direct"),
            ("group", "Group"),
            ("channel", "Channel"),
        ],
    )
    title = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True)
    avatar_url = models.CharField(max_length=255, null=True)
    creator = models.ForeignKey(User, on_delete=models.PROTECT)
    settings = models.JSONField(null=True)
    last_message = models.ForeignKey(
        "Message", on_delete=models.SET_NULL, related_name="+", null=True
    )
    last_activity_at = models.DateTimeField(null=True)
    is_encrypted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Participant(models.Model):
    conversation = models.ForeignKey(
        Conversation, on_delete=models.CASCADE, related_name="participants"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="participations"
    )
    role = models.CharField(
        max_length=20,
        choices=[
            ("owner", "Owner"),
            ("admin", "Admin"),
            ("moderator", "Moderator"),
            ("member", "Member"),
        ],
        default="member",
    )
    nickname = models.CharField(max_length=50, null=True)
    last_read_message = models.ForeignKey(
        "Message", on_delete=models.SET_NULL, null=True
    )
    is_muted = models.BooleanField(default=False)
    mute_until = models.DateTimeField(null=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True)


class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    sender = models.ForeignKey(User, on_delete=models.PROTECT)
    reply_to = models.ForeignKey("self", null=True, on_delete=models.SET_NULL)
    type = models.CharField(
        max_length=20,
        choices=[
            ("text", "Text"),
            ("image", "Image"),
            ("video", "Video"),
            ("audio", "Audio"),
            ("file", "File"),
            ("document", "Document"),
            ("location", "Location"),
            ("contact", "Contact"),
            ("poll", "Poll"),
            ("sticker", "Sticker"),
            ("system", "System"),
        ],
    )
    content = models.TextField()
    metadata = models.JSONField(null=True)
    is_encrypted = models.BooleanField(default=False)
    is_edited = models.BooleanField(default=False)
    edit_history = models.JSONField(null=True)
    delivered_at = models.DateTimeField(null=True)
    read_by = models.JSONField(null=True)
    reactions = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True)
