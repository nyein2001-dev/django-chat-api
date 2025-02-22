from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("csrf-token/", views.GetCSRFToken.as_view(), name="csrf-token"),
]
