from django.test import TestCase, RequestFactory, Client
from django.urls import reverse
from django.contrib.sessions.middleware import SessionMiddleware
from django.conf import settings
from datetime import datetime, timedelta
import json
import time
import os
import tempfile
from unittest.mock import patch, MagicMock
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from .models import UserRole, Category, User, Article, FeatureImage, ActivityLog
from .views import (
    generate_token, verify_token, check_session_timeout, 
    role_required, login_required, login, logout,
    pending_view, posted_view, create_view, edit_profile,
    logs, user_management, create_article, update_article,
    handle_publish_draft, handle_feature_image, delete_article,
    unpublish_article, article_page
)

class LoginViewTest(TestCase):

    def setUp(self):
        self.editorial_role = UserRole.objects.create(role_id=1, role_name="Editorial Board")
        self.copyreader_role = UserRole.objects.create(role_id=2, role_name="Copyreader")
        self.generalstaff_role = UserRole.objects.create(role_id=3, role_name="General Staff")
        self.editorial_user = User.objects.create(username="editorial", email="editorial@example.com", first_name="Editorial", last_name="User", password="password123", role=self.editorial_role)
        self.copyreader_user = User.objects.create(username="copyreader", email="copyreader@example.com", first_name="Copyreader", last_name="User", password="password123", role=self.copyreader_role)
        self.generalstaff_user = User.objects.create(username="generalstaff", email="generalstaff@example.com", first_name="General Staff", last_name="User", password="password123", role=self.generalstaff_role)
        self.client = Client()

    def test_login_page_loads(self):
        response = self.client.get(reverse('CRU:Login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/login.html')

    def test_login_successful_editorial(self):
        # Test that editorial user can login successfully and session is set
        response = self.client.post(reverse('CRU:Login'), {'username': 'editorial', 'password': 'password123'})
        self.assertRedirects(response, reverse('CRU:DashboardPending'))
        self.assertEqual(self.client.session['user_id'], self.editorial_user.user_id)
        self.assertEqual(self.client.session['role_id'], 1)
        self.assertEqual(self.client.session['username'], 'editorial')
        self.assertIn('token', self.client.session)
        log = ActivityLog.objects.filter(user=self.editorial_user, action_type='Login').first()
        self.assertIsNotNone(log)

    def test_login_successful_copyreader(self):
        # Test that copyreader user can login and session is set properly
        response = self.client.post(reverse('CRU:Login'), {'username': 'copyreader', 'password': 'password123'})
        self.assertRedirects(response, reverse('CRU:DashboardPending'))
        self.assertEqual(self.client.session['user_id'], self.copyreader_user.user_id)
        self.assertEqual(self.client.session['role_id'], 2)
        self.assertEqual(self.client.session['username'], 'copyreader')
        self.assertIn('token', self.client.session)

    def test_login_invalid_credentials(self):
        # Test login attempt with invalid credentials returns error
        response = self.client.post(reverse('CRU:Login'), {'username': 'copyreader', 'password': 'wrongpassword'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/login.html')
        self.assertContains(response, 'Invalid credentials')

    def test_login_nonexistent_user(self):
        # Test login with a username not tied to a user returns error
        response = self.client.post(reverse('CRU:Login'), {'username': 'nonexistent', 'password': 'password123'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/login.html')
        self.assertContains(response, 'User does not exist')

    @patch('CRU.views.generate_token')
    def test_token_generation(self, mock_generate_token):
        # Test that login triggers token generation and stores it in session
        mock_generate_token.return_value = 'test-token'
        response = self.client.post(reverse('CRU:Login'), {'username': 'editorial', 'password': 'password123'})
        mock_generate_token.assert_called_once_with(self.editorial_user.user_id, self.editorial_user.role.role_id)
        self.assertEqual(self.client.session['token'], 'test-token')


class LogoutViewTest(TestCase):

    def setUp(self):
        self.role = UserRole.objects.create(role_name="Test Role")
        self.user = User.objects.create(username="testuser", email="test@example.com", password="testpassword", role=self.role)
        self.client = Client()
        self.client.post(reverse('CRU:Login'), {'email': 'test@example.com', 'password': 'testpassword'})

    def test_logout_clears_session(self):
        # Test that logout removes all session keys
        self.assertIn('user_id', self.client.session)
        response = self.client.get(reverse('CRU:Logout'))
        self.assertRedirects(response, reverse('CRU:Login'))
        self.assertNotIn('user_id', self.client.session)
        self.assertNotIn('role_id', self.client.session)
        self.assertNotIn('username', self.client.session)
        self.assertNotIn('token', self.client.session)

    def test_logout_creates_activity_log(self):
        log_count = ActivityLog.objects.filter(user=self.user, action_type='Logout').count()
        self.client.get(reverse('CRU:Logout'))
        new_log_count = ActivityLog.objects.filter(user=self.user, action_type='Logout').count()
        self.assertEqual(new_log_count, log_count + 1)

    def test_logout_nonexistent_user(self):
        # Test logout attempt with nonexistent session user redirects
        session = self.client.session
        session['user_id'] = 9999
        session.save()
        response = self.client.get(reverse('CRU:Logout'))
        self.assertRedirects(response, reverse('CRU:Login'))


class EditProfileViewTest(TestCase):

    def setUp(self):
        self.role = UserRole.objects.create(role_id=1, role_name="Editorial Board")
        self.user = User.objects.create(username="testuser", email="test@example.com", first_name="Test", last_name="User", password="testpassword", role=self.role)
        self.client = Client()
        self.client.post(reverse('CRU:Login'), {'email': 'test@example.com', 'password': 'testpassword'})

    def test_edit_profile_page_loads(self):
        # Test that profile editing page loads with user context
        response = self.client.get(reverse('CRU:EditProfile'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/edit_profile.html')
        self.assertEqual(response.context['user'], self.user)

    def test_edit_profile_unauthorized(self):
        # Test unauthorized access to profile page redirects
        self.client.get(reverse('CRU:Logout'))
        response = self.client.get(reverse('CRU:EditProfile'))
        self.assertRedirects(response, reverse('CRU:Login'))

    def test_update_profile_info(self):
        # Test updating first name, last name, and email with valid current password
        response = self.client.post(reverse('CRU:EditProfile'), {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com',
            'current_password': 'testpassword'
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
        self.assertEqual(self.user.email, 'updated@example.com')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile updated successfully')
        log = ActivityLog.objects.filter(user=self.user, action_type='Profile Update').exists()
        self.assertTrue(log)

    def test_update_password(self):
        # Test successful password update
        response = self.client.post(reverse('CRU:EditProfile'), {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'current_password': 'testpassword',
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        })
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile updated successfully')

    def test_password_mismatch(self):
        # Test password update failure due to mismatched new passwords
        response = self.client.post(reverse('CRU:EditProfile'), {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'current_password': 'testpassword',
            'new_password': 'newpassword123',
            'confirm_password': 'differentpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'New passwords do not match')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('testpassword'))

    def test_incorrect_current_password(self):
        # Test password update failure due to incorrect current password
        response = self.client.post(reverse('CRU:EditProfile'), {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com',
            'current_password': 'wrongpassword',
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Current password is incorrect')
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Test')
        self.assertEqual(self.user.last_name, 'User')
        self.assertEqual(self.user.email, 'test@example.com')


class CreateProfileTest(TestCase):

    def setUp(self):
        self.editorial_role = UserRole.objects.create(role_id=1, role_name="Editorial Board")
        self.writer_role = UserRole.objects.create(role_id=2, role_name="Writer")
        self.admin_user = User.objects.create(
            username="admin",
            email="admin@example.com",
            first_name="Admin",
            last_name="User",
            password="adminpassword",
            role=self.editorial_role
        )
        
        self.regular_user = User.objects.create(
            username="regular",
            email="regular@example.com",
            first_name="Regular",
            last_name="User",
            password="regularpassword",
            role=self.writer_role
        )
        
        self.client = Client()
    
    def test_create_user_authorized(self):
        # Test that admin can create a new user with proper role assignment
        self.client.post(reverse('CRU:Login'), {
            'email': 'admin@example.com',
            'password': 'adminpassword'
        })
        response = self.client.post(reverse('CRU:UserManagement'), {
            'action': 'create_user',
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newuserpassword',
            'first_name': 'New',
            'last_name': 'User',
            'role': self.writer_role.role_id
        })
        self.assertTrue(User.objects.filter(username='newuser').exists())
        new_user = User.objects.get(username='newuser')
        self.assertEqual(new_user.email, 'newuser@example.com')
        self.assertEqual(new_user.first_name, 'New')
        self.assertEqual(new_user.last_name, 'User')
        self.assertEqual(new_user.role, self.writer_role)
        log = ActivityLog.objects.filter(
            user=self.admin_user,
            action_type='User Creation'
        ).exists()
        self.assertTrue(log)
    
    def test_create_user_duplicate_username(self):
        # Test that creating user with existing username returns error
        self.client.post(reverse('CRU:Login'), {
            'email': 'admin@example.com',
            'password': 'adminpassword'
        })
        response = self.client.post(reverse('CRU:UserManagement'), {
            'action': 'create_user',
            'username': 'regular',
            'email': 'different@example.com',
            'password': 'password123',
            'first_name': 'New',
            'last_name': 'User',
            'role': self.writer_role.role_id
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Username already exists')
    
    def test_create_user_duplicate_email(self):
        # Test that creating user with existing email returns error
        self.client.post(reverse('CRU:Login'), {
            'email': 'admin@example.com',
            'password': 'adminpassword'
        })
        response = self.client.post(reverse('CRU:UserManagement'), {
            'action': 'create_user',
            'username': 'uniqueuser',
            'email': 'regular@example.com',
            'password': 'password123',
            'first_name': 'New',
            'last_name': 'User',
            'role': self.writer_role.role_id
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Email already exists')


class ArticleManagementTest(TestCase):
    
    def setUp(self):
        # Create user roles
        self.editorial_role = UserRole.objects.create(role_id=1, role_name="Editorial Board")
        self.copyreader_role = UserRole.objects.create(role_id=2, role_name="Copyreader")
        self.writer_role = UserRole.objects.create(role_id=3, role_name="Writer")
        
        # Create test users
        self.editorial_user = User.objects.create(
            username="editorial",
            email="editorial@example.com",
            first_name="Editorial",
            last_name="User",
            password="password123",
            role=self.editorial_role
        )
        
        self.copyreader_user = User.objects.create(
            username="copyreader",
            email="copyreader@example.com",
            first_name="Copyreader",
            last_name="User",
            password="password123",
            role=self.copyreader_role
        )
        
        self.writer_user = User.objects.create(
            username="writer",
            email="writer@example.com",
            first_name="Writer",
            last_name="User",
            password="password123",
            role=self.writer_role
        )
        
        # Create test categories
        self.category1 = Category.objects.create(name="News")
        self.category2 = Category.objects.create(name="Sports")
        
        # Create client
        self.client = Client()
        
        # Create test article
        self.article = Article.objects.create(
            title="Test Article",
            content="<p>This is a test article content.</p>",
            author=self.writer_user,
            category=self.category1,
            status=False,
            CopyReader_Status=False,
            Editorial_Status=False
        )
    
    def login_user(self, username, password):
        return self.client.post(reverse('CRU:Login'), {
            'username': username,
            'password': password
        })
    
    def test_create_article_view_loads(self):
        # Test that create article page loads for authenticated users - Expected: page loads with categories
        self.login_user('writer', 'password123')
        response = self.client.get(reverse('CRU:NewArticle'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/create.html')
        self.assertIn('categories', response.context)
    
    def test_create_article_unauthorized(self):
        # Test unauthenticated access to create article page - Expected: redirect to login
        response = self.client.get(reverse('CRU:NewArticle'))
        self.assertRedirects(response, reverse('CRU:Login'))
    
    def test_create_article_submission(self):
        # Test creating a new article with valid data - Expected: article created with correct properties
        self.login_user('writer', 'password123')
        
        article_count_before = Article.objects.count()
        
        response = self.client.post(reverse('CRU:NewArticle'), {
            'title': 'New Test Article',
            'content': '<p>This is a new test article content.</p>',
            'category': self.category1.category_id,
            'action': 'submitDraft'
        })
        
        # Check that article was created
        self.assertEqual(Article.objects.count(), article_count_before + 1)
        
        # Get the newly created article
        new_article = Article.objects.latest('created_at')
        
        # Check article properties
        self.assertEqual(new_article.title, 'New Test Article')
        self.assertEqual(new_article.content, '<p>This is a new test article content.</p>')
        self.assertEqual(new_article.author, self.writer_user)
        self.assertEqual(new_article.category, self.category1)
        self.assertFalse(new_article.status)
        self.assertFalse(new_article.CopyReader_Status)
        self.assertFalse(new_article.Editorial_Status)
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.writer_user,
            action_type='Create Article'
        ).exists()
        self.assertTrue(log)
    
    def test_update_article(self):
        # Test updating an existing article - Expected: article properties updated in database
        self.login_user('writer', 'password123')
        
        response = self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': 'Updated Test Article',
            'content': '<p>This is updated content.</p>',
            'category': self.category2.category_id,
            'action': 'submitDraft'
        })
        
        # Refresh article from database
        self.article.refresh_from_db()
        
        # Check article was updated
        self.assertEqual(self.article.title, 'Updated Test Article')
        self.assertEqual(self.article.content, '<p>This is updated content.</p>')
        self.assertEqual(self.article.category, self.category2)
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.writer_user,
            action_type='Update Article'
        ).exists()
        self.assertTrue(log)
    
    def test_copyreader_approval(self):
        # Test copyreader can approve an article - Expected: CopyReader_Status set to true
        self.login_user('copyreader', 'password123')
        
        response = self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': self.article.title,
            'content': self.article.content,
            'category': self.article.category.category_id,
            'CopyReader_Status': 'on',
            'action': 'submitDraft'
        })
        
        # Refresh article from database
        self.article.refresh_from_db()
        
        # Check copyreader status was updated
        self.assertTrue(self.article.CopyReader_Status)
        self.assertFalse(self.article.status)  # Article should not be published yet
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.copyreader_user,
            action_type='Article Approval',
            action_details__contains='approved'
        ).exists()
        self.assertTrue(log)
    
    def test_editorial_approval(self):
        # Test editorial board can approve an article - Expected: Editorial_Status set to true
        self.login_user('editorial', 'password123')
        
        response = self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': self.article.title,
            'content': self.article.content,
            'category': self.article.category.category_id,
            'Editorial_Status': 'on',
            'action': 'submitDraft'
        })
        
        # Refresh article from database
        self.article.refresh_from_db()
        
        # Check editorial status was updated
        self.assertTrue(self.article.Editorial_Status)
        self.assertFalse(self.article.status)  # Article should not be published yet
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.editorial_user,
            action_type='Article Approval',
            action_details__contains='approved'
        ).exists()
        self.assertTrue(log)
    
    def test_publish_article(self):
        # Test article publishing with both approvals - Expected: article status set to published
        # First set copyreader approval
        self.login_user('copyreader', 'password123')
        self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': self.article.title,
            'content': self.article.content,
            'category': self.article.category.category_id,
            'CopyReader_Status': 'on',
            'action': 'submitDraft'
        })
        
        # Then set editorial approval which should publish the article
        self.login_user('editorial', 'password123')
        self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': self.article.title,
            'content': self.article.content,
            'category': self.article.category.category_id,
            'Editorial_Status': 'on',
            'action': 'publishDraft'
        })
        
        # Refresh article from database
        self.article.refresh_from_db()
        
        # Check article is now published
        self.assertTrue(self.article.status)
        self.assertTrue(self.article.CopyReader_Status)
        self.assertTrue(self.article.Editorial_Status)
        self.assertIsNotNone(self.article.published_at)
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.editorial_user,
            action_type='Published Article'
        ).exists()
        self.assertTrue(log)
    
    def test_delete_article(self):
        # Test article deletion by editorial board - Expected: article removed from database
        self.login_user('editorial', 'password123')
        
        article_count_before = Article.objects.count()
        
        response = self.client.post(reverse('CRU:DeleteArticle', args=[self.article.article_id]))
        
        # Check article was deleted
        self.assertEqual(Article.objects.count(), article_count_before - 1)
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.editorial_user,
            action_type='Delete Article'
        ).exists()
        self.assertTrue(log)
    
    def test_unpublish_article(self):
        # Test unpublishing a published article - Expected: article status reverted to draft
        # First publish the article
        self.article.CopyReader_Status = True
        self.article.Editorial_Status = True
        self.article.status = True
        self.article.published_at = datetime.now()
        self.article.save()
        
        self.login_user('editorial', 'password123')
        
        response = self.client.post(reverse('CRU:UnpublishArticle', args=[self.article.article_id]))
        
        # Refresh article from database
        self.article.refresh_from_db()
        
        # Check article is unpublished
        self.assertFalse(self.article.status)
        
        # Check activity log was created
        log = ActivityLog.objects.filter(
            user=self.editorial_user,
            action_type='Unpublish Article'
        ).exists()
        self.assertTrue(log)
    
    def test_article_page_view(self):
        # Test public article page view - Expected: page loads with article content
        # Publish the article
        self.article.CopyReader_Status = True
        self.article.Editorial_Status = True
        self.article.status = True
        self.article.published_at = datetime.now()
        self.article.save()
        
        response = self.client.get(reverse('CRU:ArticlePage', args=[self.article.article_id]))
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'public_view/article_page.html')
        
    def test_pending_view(self):
        # Test pending articles dashboard - Expected: page loads with pending articles
        self.login_user('editorial', 'password123')
        
        response = self.client.get(reverse('CRU:DashboardPending'))
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/pending.html')
        self.assertIn('articles', response.context)
        self.assertIn('base_template', response.context)
    
    def test_posted_view(self):
        # Test posted articles dashboard - Expected: page loads with published articles
        # Publish the article
        self.article.status = True
        self.article.published_at = datetime.now()
        self.article.save()
        
        self.login_user('editorial', 'password123')
        
        response = self.client.get(reverse('CRU:DashboardPosted'))
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'genadmin_view/posted.html')
        self.assertIn('articles', response.context)
        self.assertIn('is_editorialboard', response.context)
        self.assertTrue(response.context['is_editorialboard'])
    
    @patch('CRU.views.handle_feature_image')
    def test_feature_image_upload(self, mock_handle_feature_image):
        # Test feature image upload - Expected: handle_feature_image function called
        mock_handle_feature_image.return_value = True
        
        self.login_user('writer', 'password123')
        
        # Create a test image file
        image = SimpleUploadedFile(
            name='test_image.jpg',
            content=b'',  # Empty content for test
            content_type='image/jpeg'
        )
        
        response = self.client.post(reverse('CRU:EditArticle', args=[self.article.article_id]), {
            'title': self.article.title,
            'content': self.article.content,
            'category': self.article.category.category_id,
            'feature_image': image,
            'action': 'submitDraft'
        })
        
        # Check that handle_feature_image was called
        mock_handle_feature_image.assert_called_once()
    
    def test_conditional_navigation(self):
        # Test role-based context variables in article page - Expected: correct flags set for each role
        # Publish the article
        self.article.CopyReader_Status = True
        self.article.Editorial_Status = True
        self.article.status = True
        self.article.published_at = datetime.now()
        self.article.save()
        
        # Test for editorial board user
        self.login_user('editorial', 'password123')
        response = self.client.get(reverse('CRU:ArticlePage', args=[self.article.article_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['is_logged_in'])
        self.assertTrue(response.context['is_editorialboard'])
        self.assertFalse(response.context['is_copyreader'])
        self.assertFalse(response.context['is_generalstaff'])
        
        # Test for copyreader user
        self.login_user('copyreader', 'password123')
        response = self.client.get(reverse('CRU:ArticlePage', args=[self.article.article_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['is_logged_in'])
        self.assertFalse(response.context['is_editorialboard'])
        self.assertTrue(response.context['is_copyreader'])
        self.assertFalse(response.context['is_generalstaff'])
        
        # Test for general staff user (writer)
        self.login_user('writer', 'password123')
        response = self.client.get(reverse('CRU:ArticlePage', args=[self.article.article_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['is_logged_in'])
        self.assertFalse(response.context['is_editorialboard'])
        self.assertFalse(response.context['is_copyreader'])
        self.assertTrue(response.context['is_generalstaff'])
        
        # Test for non-logged-in user
        self.client.get(reverse('CRU:Logout'))
        response = self.client.get(reverse('CRU:ArticlePage', args=[self.article.article_id]))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['is_logged_in'])
        self.assertFalse(response.context['is_editorialboard'])
        self.assertFalse(response.context['is_copyreader'])
        self.assertFalse(response.context['is_generalstaff'])


class PublicViewSearchTest(TestCase):
    def setUp(self):
        # Create user roles similar to other tests
        self.editorial_role = UserRole.objects.create(role_id=1, role_name="Editorial Board")
        self.copyreader_role = UserRole.objects.create(role_id=2, role_name="Copyreader")
        self.generalstaff_role = UserRole.objects.create(role_id=3, role_name="General Staff")
        
        # Create test users
        self.editorial_user = User.objects.create(
            username="editorial", 
            email="editorial@example.com", 
            password="password123", 
            role=self.editorial_role
        )
        
        self.generalstaff_user = User.objects.create(
            username="generalstaff", 
            email="generalstaff@example.com", 
            password="password123", 
            role=self.generalstaff_role
        )
        
        # Create the specific categories
        self.university_news = Category.objects.create(
            name="University News", 
            description="University news and updates"
        )
        self.editorial = Category.objects.create(
            name="Editorial", 
            description="Editorial content"
        )
        self.opinions = Category.objects.create(
            name="Opinions", 
            description="Opinion pieces"
        )
        self.in_photos = Category.objects.create(
            name="In Photos", 
            description="Photo essays"
        )
        self.satire = Category.objects.create(
            name="Satire", 
            description="Satirical content"
        )
        
        # Create test articles for each category
        self.news_article = Article.objects.create(
            title="Campus Renovation Project",
            content="<p>The university starts a new <strong>renovation</strong> project.</p>",
            category=self.university_news,
            author=self.generalstaff_user,
            status=True,
            published_at=timezone.now()
        )
        
        self.editorial_article = Article.objects.create(
            title="State of Student Journalism",
            content="<p>An analysis of student journalism in universities.</p>",
            category=self.editorial,
            author=self.editorial_user,
            status=True,
            published_at=timezone.now() - timedelta(days=1)
        )
        
        self.opinion_article = Article.objects.create(
            title="Student Voice Matters",
            content="<p>Why student opinions should be heard.</p>",
            category=self.opinions,
            author=self.generalstaff_user,
            status=True,
            published_at=timezone.now() - timedelta(days=2)
        )
        
        self.photo_article = Article.objects.create(
            title="Campus Life in Pictures",
            content="<p>A photo essay of daily student life.</p>",
            category=self.in_photos,
            author=self.editorial_user,
            status=True,
            published_at=timezone.now() - timedelta(days=3)
        )
        
        self.satire_article = Article.objects.create(
            title="Professors Actually Robots",
            content="<p>Shocking revelation: All professors are robots in disguise!</p>",
            category=self.satire,
            author=self.generalstaff_user,
            status=True,
            published_at=timezone.now() - timedelta(days=4)
        )
        
        # Create an unpublished article
        self.unpublished_article = Article.objects.create(
            title="Draft Article",
            content="<p>This is an unpublished article.</p>",
            category=self.university_news,
            author=self.generalstaff_user,
            status=False
        )
        
        self.client = Client()
    
    def test_search_page_loads(self):
        # Test that the search page loads correctly - Expected: page loads with status 200
        response = self.client.get(reverse('CRU:Search'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'public_view/search.html')
    
    def test_search_results_page_loads(self):
        # Test that the search results page loads correctly - Expected: page loads with status 200
        response = self.client.get(reverse('CRU:SearchCategories'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'public_view/searched_page.html')
    
    def test_categories_in_context(self):
        # Test that all required categories are available in the search context - Expected: all 5 categories present
        response = self.client.get(reverse('CRU:SearchCategories'))
        categories = list(response.context['categories'])
        self.assertEqual(len(categories), 5)
        category_names = {category.name for category in categories}
        expected_categories = {
            'University News',
            'Editorial',
            'Opinions',
            'In Photos',
            'Satire'
        }
        self.assertEqual(category_names, expected_categories)
    
    def test_search_by_category(self):
        # Test search by each category - Expected: correct article found for each category
        categories = [
            ('University News', 'Campus Renovation Project'),
            ('Editorial', 'State of Student Journalism'),
            ('Opinions', 'Student Voice Matters'),
            ('In Photos', 'Campus Life in Pictures'),
            ('Satire', 'Professors Actually Robots')
        ]
        
        for category_name, expected_title in categories:
            response = self.client.get(reverse('CRU:SearchCategories'), {'category': category_name})
            self.assertEqual(response.status_code, 200)
            articles = list(response.context['articles'])
            self.assertEqual(len(articles), 1)
            self.assertEqual(articles[0].title, expected_title)
    
    def test_search_by_title(self):
        # Test search by article title - Expected: both articles with 'Campus' in title found
        response = self.client.get(reverse('CRU:SearchCategories'), {'q': 'Campus'})
        self.assertEqual(response.status_code, 200)
        articles = list(response.context['articles'])
        self.assertEqual(len(articles), 2)  # Should find both Campus articles
        titles = {article.title for article in articles}
        self.assertEqual(titles, {'Campus Renovation Project', 'Campus Life in Pictures'})
    
    def test_search_by_content(self):
        # Test search by article content - Expected: article with matching content found
        response = self.client.get(reverse('CRU:SearchCategories'), {'q': 'renovation'})
        self.assertEqual(response.status_code, 200)
        articles = list(response.context['articles'])
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0].title, 'Campus Renovation Project')
    
    def test_search_with_category_and_query(self):
        # Test search with both query and category filter - Expected: only articles matching both criteria found
        response = self.client.get(reverse('CRU:SearchCategories'), {
            'q': 'Campus',
            'category': 'University News'
        })
        self.assertEqual(response.status_code, 200)
        articles = list(response.context['articles'])
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0].title, 'Campus Renovation Project')
    
    def test_search_excludes_unpublished(self):
        # Test that unpublished articles are not included in search results - Expected: no results for draft article
        response = self.client.get(reverse('CRU:SearchCategories'), {'q': 'Draft'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['articles']), 0)
    
    def test_empty_search_results(self):
        # Test search with no query parameters - Expected: empty results with template loaded
        response = self.client.get(reverse('CRU:SearchCategories'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'public_view/searched_page.html')
        self.assertEqual(len(response.context['articles']), 0)
        self.assertEqual(response.context['query'], '')
        self.assertEqual(response.context['category_filter'], '')
    
    def test_search_case_insensitive(self):
        # Test that search is case-insensitive - Expected: same results for 'campus' as for 'Campus'
        response = self.client.get(reverse('CRU:SearchCategories'), {'q': 'campus'})
        self.assertEqual(response.status_code, 200)
        articles = list(response.context['articles'])
        self.assertEqual(len(articles), 2)
        titles = {article.title for article in articles}
        self.assertEqual(titles, {'Campus Renovation Project', 'Campus Life in Pictures'})
    
