from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'conversations', views.ConversationViewSet, basename='conversation')
router.register(r'messages', views.MessageViewSet, basename='message')

message_list = views.MessageViewSet.as_view({
    'get': 'list',
    'post': 'create'
})
message_detail = views.MessageViewSet.as_view({
    'get': 'retrieve',
    'put': 'update',
    'patch': 'partial_update',
    'delete': 'destroy'
})
message_read = views.MessageViewSet.as_view({
    'post': 'mark_read'
})

urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    
    path('messages/', message_list, name='message-list'),
    path('messages/<int:pk>/', message_detail, name='message-detail'),
    path('messages/<int:pk>/mark_read/', message_read, name='message-mark-read'),
] 