from django.urls import path
from . import views

app_name = 'CRU'

urlpatterns = [
    path('', views.home, name='Home'),
    path('login/', views.login, name='Login'),
    path('pending/', views.pending_view, name="DashboardPending"),
    path('posted/', views.posted_view, name="DashboardPosted"),
    path('create-article/', views.create_view, name="NewArticle"),
    path('edit-profile/', views.edit_profile, name="EditProfile"),
    path('logs/', views.logs, name="Logs"),
    path('user-management/', views.user_management, name="UserManagement"),
    path('about/', views.about, name="About"),
    path('search/', views.search, name="Search"),
]
