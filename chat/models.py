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
