from django.urls import path
from . import views

app_name = 'CRU'

urlpatterns = [
    path('', views.home, name='Home'),
    path('login/', views.login, name='Login'),
    path('logout/', views.logout, name='Logout'),
    path('pending/', views.pending_view, name="DashboardPending"),
    path('posted/', views.posted_view, name="DashboardPosted"),
    path('create-article/', views.create_view, name="NewArticle"),
    path('edit-profile/', views.edit_profile, name="EditProfile"),
    path('logs/', views.logs, name="Logs"),
    path('user-management/', views.user_management, name="UserManagement"),
    path('article/create/', views.create_view, name='ArticleCreate'),
    path('article/edit/<int:article_id>/', views.create_view, name='EditArticle'),
    path('article/<int:article_id>/', views.article_page, name='ArticlePage'),
    path('article/delete/<int:article_id>/', views.delete_article, name='DeleteArticle'),
    path('article/unpublish/<int:article_id>/', views.unpublish_article, name='UnpublishArticle'),
    path('search/', views.search, name="Search"),
    path('search-results', views.search_page, name="SearchCategories"),
]
