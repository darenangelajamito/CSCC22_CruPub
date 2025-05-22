import json
import os
import time
import re
from datetime import datetime, timedelta
from functools import wraps
from django.db import models
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import jwt

from .models import User, UserRole, Article, Category, FeatureImage, ActivityLog


def generate_token(user_id, role_id):
    payload = {
        'user_id': user_id,
        'role_id': role_id,
        'exp': datetime.now() + timedelta(minutes=30),
        'iat': datetime.now()
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def verify_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def check_session_timeout(request):
    last_activity = request.session.get('last_activity')
    if last_activity:
        elapsed_time = time.time() - float(last_activity)
        if elapsed_time > 1800:  
            return False
    request.session['last_activity'] = str(time.time())
    return True


def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not check_session_timeout(request):
                request.session.flush()
                return redirect('CRU:Login')
            
            if not request.session.get('user_id'):
                return HttpResponse("Unauthorized", status=401)
            
            user_role = request.session.get('role_id')
            if user_role not in allowed_roles:
                return HttpResponse("Forbidden", status=403)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not check_session_timeout(request):
            request.session.flush()
            return redirect('CRU:Login')
        
        if not request.session.get('user_id'):
            return HttpResponse("Unauthorized", status=401)
        
        return view_func(request, *args, **kwargs)
    return wrapper


def home(request):
    published_articles = Article.objects.filter(status=True).order_by('-published_at')
    
    context = {
        'articles': published_articles,
        'featured_article': published_articles.first() if published_articles.exists() else None
    }
    
    return render(request, 'public_view/home.html', context)


def search(request):
    return render(request, 'public_view/search.html')


def strip_html_tags(html_content):
    clean_text = re.sub(r'<[^>]*>', ' ', html_content)
    clean_text = re.sub(r'&[a-zA-Z]+;', ' ', clean_text)
    clean_text = re.sub(r'\s+', ' ', clean_text)
    return clean_text.strip()


def search_page(request):   
    query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()
    
    articles = []
    categories = Category.objects.all()
    
    if query or category_filter:
        article_query = Article.objects.filter(status=True)
        
        if query:
            article_query = article_query.filter(
                models.Q(title__icontains=query) | 
                models.Q(content__icontains=query) |
                models.Q(author_name__icontains=query)
            )
        
        if category_filter:
            article_query = article_query.filter(
                category__name__iexact=category_filter
            )
        
        if query and not category_filter:
            matching_categories = Category.objects.filter(name__iexact=query)
            if matching_categories.exists():
                category_articles = Article.objects.filter(
                    category__in=matching_categories,
                    status=True
                )
                article_query = article_query | category_articles
        
        articles = article_query.distinct().order_by('-published_at')
        
        for article in articles:
            article.clean_content = strip_html_tags(article.content)
    
    context = {
        "query": query,
        "category_filter": category_filter,
        "articles": articles,
        "categories": categories,
        "total_results": len(articles)
    }
    return render(request, 'public_view/searched_page.html', context)


def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                token = generate_token(user.user_id, user.role.role_id)
                
                request.session['user_id'] = user.user_id
                request.session['role_id'] = user.role.role_id
                request.session['username'] = user.username
                request.session['email'] = user.email
                request.session['token'] = token
                request.session['last_activity'] = str(time.time())
                
                ActivityLog.objects.create(
                    user=user,
                    action_type='Login',
                    action_details='User logged in'
                )
                
                return redirect('CRU:DashboardPending')
            else:
                return render(request, 'genadmin_view/login.html', {'error': 'Invalid credentials'})
        except User.DoesNotExist:
            return render(request, 'genadmin_view/login.html', {'error': 'User does not exist'})
    
    return render(request, 'genadmin_view/login.html')


def logout(request):
    if request.session.get('user_id'):
        try:
            user = User.objects.get(pk=request.session.get('user_id'))
            ActivityLog.objects.create(
                user=user,
                action_type='Logout',
                action_details='User logged out'
            )
        except User.DoesNotExist:
            pass
    
    request.session.flush()
    return redirect('CRU:Login')


def get_user_context(request, article=None, article_id=None, error=None):
    user_role = request.session.get('role_id')
    return {
        'categories': Category.objects.all(),
        'base_template': 'base_eb.html' if user_role == 1 else 'base_noneb.html',
        'role_id': user_role,
        'is_generalstaff': user_role == 3,
        'is_copyreader': user_role == 2,
        'is_editorialboard': user_role == 1,
        'article': article,
        'article_id': article_id if article else None,
        'error': error
    }


@role_required([1, 2, 3])
def create_view(request, article_id=None):
    article = None
    if article_id:
        article = get_object_or_404(Article, pk=article_id)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
        category_id = request.POST.get('category')
        journalist = request.POST.get('journalist')
        author_name = request.POST.get('author_name')
        action = request.POST.get('action')
        remove_image = request.POST.get('removeImage') == 'true'
        
        if not title or not content or not category_id:
            context = get_user_context(request, article, article_id, 'All fields are required')
            context.update({
                'form_data': {
                    'title': title,
                    'content': content,
                    'category_id': category_id,
                    'journalist': journalist,
                    'author_name': author_name
                }
            })
            return render(request, 'genadmin_view/create.html', context)
        
        try:
            if not article:  
                article = create_article(request, title, content, category_id, author_name)
                article_id = article.article_id
            else:  
                article = update_article(request, article, title, content, category_id, action, author_name)
            
            handle_feature_image(request, article, journalist, remove_image)
            
            if action == 'publishDraft' and article.status:
                return redirect('CRU:ArticlePage', article_id=article_id)
            elif action == 'publishDraft':
                return redirect('CRU:DashboardPending')
            elif action == 'submitDraft':
                return redirect('CRU:DashboardPending')
            
            context = get_user_context(request, article, article_id)
            return render(request, 'genadmin_view/create.html', context)
        except Exception as e:
            context = get_user_context(request, article, article_id, str(e))
            return render(request, 'genadmin_view/create.html', context)
                
    context = get_user_context(request, article, article_id)
    return render(request, 'genadmin_view/create.html', context)


def create_article(request, title, content, category_id, author_name=None):
    category = get_object_or_404(Category, pk=category_id)
    creator = get_object_or_404(User, pk=request.session.get('user_id'))
    user_role = request.session.get('role_id')
    
    # Use provided author_name if available, otherwise use creator's name
    if not author_name:
        author_name = f"{creator.first_name} {creator.last_name}".strip() or creator.username
    
    article = Article.objects.create(
        title=title,
        content=content,
        articlecreatedby=creator,
        author_name=author_name,
        status=False,
        CopyReader_Status=True if user_role == 2 else False,
        Editorial_Status=False,
        category=category,
        created_at=datetime.now()
    )
    
    ActivityLog.objects.create(
        user=creator,
        action_type='Create Article',
        action_details=f'Created article: {article.title}'
    )
    
    return article


def update_article(request, article, title, content, category_id, action, author_name=None):
    category = get_object_or_404(Category, pk=category_id)
    user = get_object_or_404(User, pk=request.session.get('user_id'))
    user_role = request.session.get('role_id')
    
    original_copyreader_status = article.CopyReader_Status
    original_editorial_status = article.Editorial_Status
    
    article.title = title
    article.content = content
    article.category = category
    
    # Update author_name if provided
    if author_name:
        article.author_name = author_name
        
    article.updated_at = datetime.now()
    
    if user_role == 2:  
        new_copyreader_status = request.POST.get('CopyReader_Status') == 'on'
        article.CopyReader_Status = new_copyreader_status
        
        if original_copyreader_status != new_copyreader_status:
            approval_action = "approved" if new_copyreader_status else "unapproved"
            ActivityLog.objects.create(
                user=user,
                action_type='Article Approval',
                action_details=f'Copyreader {approval_action} article: {article.title}'
            )
            
    elif user_role == 1:  
        new_editorial_status = request.POST.get('Editorial_Status') == 'on'
        article.Editorial_Status = new_editorial_status
        
        if original_editorial_status != new_editorial_status:
            approval_action = "approved" if new_editorial_status else "unapproved"
            ActivityLog.objects.create(
                user=user,
                action_type='Article Approval',
                action_details=f'Editorial Board {approval_action} article: {article.title}'
            )
    
    if action == 'submitDraft':
        article.save()
        ActivityLog.objects.create(
            user=user,
            action_type='Update Article',
            action_details=f'Updated article: {article.title}'
        )
    
    if action == 'publishDraft':
        handle_publish_draft(request, article, user)
        
    return article


def handle_publish_draft(request, article, user):
    user_role = request.session.get('role_id')
    
    original_copyreader_status = article.CopyReader_Status
    original_editorial_status = article.Editorial_Status
    
    if user_role == 1:  
        if not original_editorial_status:
            ActivityLog.objects.create(
                user=user,
                action_type='Article Approval',
                action_details=f'Editorial Board approved article: {article.title}'
            )
        article.Editorial_Status = True
        
    elif user_role == 2:  
        if not original_copyreader_status:
            ActivityLog.objects.create(
                user=user,
                action_type='Article Approval',
                action_details=f'Copyreader approved article: {article.title}'
            )
        article.CopyReader_Status = True
    
    if article.CopyReader_Status and article.Editorial_Status:
        article.status = True
        article.published_at = datetime.now()
        article.save()
        
        ActivityLog.objects.create(
            user=user,
            action_type='Published Article',
            action_details=f'Published article: {article.title}'
        )
        
        return True
    else:
        article.save()
        return False


def handle_feature_image(request, article, journalist, remove_image):
    import os
    from django.conf import settings
    
    os.makedirs(os.path.join(settings.MEDIA_ROOT, 'feature_images'), exist_ok=True)
    
    author = get_object_or_404(User, pk=request.session.get('user_id'))
    existing_image = FeatureImage.objects.filter(article=article).first()
    
    if remove_image and existing_image:
        if existing_image.image:
            try:
                existing_image.image.delete(save=False)
            except Exception:
                pass
        
        existing_image.delete()
        
        ActivityLog.objects.create(
            user=author,
            action_type='Remove Image',
            action_details=f'Removed image from article: {article.title}'
        )
        return True
    elif 'featureImage' in request.FILES:
        feature_image = request.FILES['featureImage']
        
        if not is_valid_image(feature_image):
            return False
            
        if existing_image:
            if existing_image.image:
                try:
                    existing_image.image.delete(save=False)
                except Exception:
                    pass
                
            existing_image.image = feature_image
            existing_image.image_url = None  
            existing_image.photo_journalist = journalist
            existing_image.save()
        else:
            FeatureImage.objects.create(
                article=article,
                image=feature_image,
                photo_journalist=journalist
            )
        
        ActivityLog.objects.create(
            user=author,
            action_type='Update Image',
            action_details=f'Updated image for article: {article.title}'
        )
        return True
    elif journalist and existing_image:
        existing_image.photo_journalist = journalist
        existing_image.save()
        return True
        
    return True  


def is_valid_image(image_file):
    
    if image_file.size > 5 * 1024 * 1024:
        return False
        
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
    ext = os.path.splitext(image_file.name)[1].lower()
    
    if ext not in valid_extensions:
        return False
        
    return True


def article_page(request, article_id):
    article = get_object_or_404(Article, pk=article_id, status=True)
    
    related_articles = Article.objects.filter(
        category=article.category, 
        status=True
    ).exclude(
        pk=article_id
    ).order_by('-published_at')[:3]
    
    is_logged_in = request.session.get('user_id') is not None
    user_role = request.session.get('role_id')
    
    context = {
        'article': article,
        'related_articles': related_articles,
        'is_logged_in': is_logged_in,
        'is_editorialboard': user_role == 1,
        'is_copyreader': user_role == 2,
        'is_generalstaff': user_role == 3
    }
    
    return render(request, 'public_view/article_page.html', context)


@role_required([1, 2, 3])
def delete_article(request, article_id):
    article = get_object_or_404(Article, pk=article_id)
    author = get_object_or_404(User, pk=request.session.get('user_id'))
    
    article_title = article.title
    was_posted = article.status
    
    article.delete()
    
    ActivityLog.objects.create(
        user=author,
        action_type='Delete Article',
        action_details=f'Deleted Article: {article_title}'
    )
    
    if was_posted:
        return redirect('CRU:DashboardPosted')
    else:
        return redirect('CRU:DashboardPending')


@role_required([1])
def unpublish_article(request, article_id):
    article = get_object_or_404(Article, pk=article_id)
    author = get_object_or_404(User, pk=request.session.get('user_id'))
    
    if article.status:
        article.status = False
        article.save()
        
        ActivityLog.objects.create(
            user=author,
            action_type='Unpublish Article',
            action_details=f'Unpublished article: {article.title}'
        )
    
    return redirect('CRU:DashboardPending')


@role_required([1, 2, 3])
def pending_view(request):
    articles = Article.objects.filter(status=False).order_by('-created_at')
    user_role = request.session.get('role_id')
    
    context = {
        'articles': articles,
        'base_template': 'base_eb.html' if user_role == 1 else 'base_noneb.html'
    }
    
    return render(request, 'genadmin_view/pending.html', context)


@role_required([1, 2, 3])
def posted_view(request):
    articles = Article.objects.filter(status=True).order_by('-published_at')
    user_role = request.session.get('role_id')
    
    context = {
        'articles': articles,
        'base_template': 'base_eb.html' if user_role == 1 else 'base_noneb.html',
        'is_editorialboard': user_role == 1,
        'is_copyreader': user_role == 2,
        'is_generalstaff': user_role == 3
    }
    
    return render(request, 'genadmin_view/posted.html', context)


@login_required
def edit_profile(request):
    user = get_object_or_404(User, pk=request.session.get('user_id'))
    user_role = request.session.get('role_id')
    base_template = 'base_eb.html' if user_role == 1 else 'base_noneb.html'
    
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        current_password = request.POST.get('current_password')
        
        if not email or not username:
            return render(request, 'genadmin_view/edit_profile.html', {
                'user': user,
                'base_template': base_template,
                'error': 'Email and username are required'
            })
            
        if not email.endswith('@my.xu.edu.ph'):
            return render(request, 'genadmin_view/edit_profile.html', {
                'user': user,
                'base_template': base_template,
                'error': 'Email must be from the @my.xu.edu.ph domain'
            })
        
        if User.objects.filter(email=email).exclude(user_id=user.user_id).exists():
            return render(request, 'genadmin_view/edit_profile.html', {
                'user': user,
                'base_template': base_template,
                'error': 'Email already exists for another user'
            })
            
        if User.objects.filter(username=username).exclude(user_id=user.user_id).exists():
            return render(request, 'genadmin_view/edit_profile.html', {
                'user': user,
                'base_template': base_template,
                'error': 'Username already exists for another user'
            })
        
        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.username = username
        
        if new_password:
            if not current_password or not user.check_password(current_password):
                return render(request, 'genadmin_view/edit_profile.html', {
                    'user': user,
                    'base_template': base_template,
                    'error': 'Current password is incorrect'
                })
            
            if len(new_password) < 8:
                return render(request, 'genadmin_view/edit_profile.html', {
                    'user': user,
                    'base_template': base_template,
                    'error': 'New password must be at least 8 characters long'
                })
            
            if new_password != confirm_password:
                return render(request, 'genadmin_view/edit_profile.html', {
                    'user': user,
                    'base_template': base_template,
                    'error': 'New passwords do not match'
                })
            
            user.password = new_password  
        
        user.save()
        
        ActivityLog.objects.create(
            user=user,
            action_type='Profile Update',
            action_details='User updated their profile information'
        )
        
        if email != request.session.get('email'):
            request.session['email'] = email
            
        if username != request.session.get('username'):
            request.session['username'] = username
        
        return render(request, 'genadmin_view/edit_profile.html', {
            'user': user,
            'base_template': base_template,
            'success': 'Profile updated successfully'
        })
    
    return render(request, 'genadmin_view/edit_profile.html', {
        'user': user,
        'base_template': base_template
    })


@role_required([1])
def logs(request):
    action_type = request.GET.get('action_type', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search_query = request.GET.get('search', '')
    
    logs_query = ActivityLog.objects.all()
    
    if action_type:
        logs_query = logs_query.filter(action_type=action_type)
    
    if user_id:
        logs_query = logs_query.filter(user_id=user_id)
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            logs_query = logs_query.filter(timestamp__date__gte=from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            logs_query = logs_query.filter(timestamp__date__lte=to_date)
        except ValueError:
            pass
    
    if search_query:
        logs_query = logs_query.filter(action_details__icontains=search_query)
    
    action_types = ActivityLog.objects.values_list('action_type', flat=True).distinct()
    users = User.objects.all().order_by('username')
    
    logs_query = logs_query.order_by('-timestamp')
    
    context = {
        'logs': logs_query,
        'action_types': action_types,
        'users': users,
        'selected_action_type': action_type,
        'selected_user_id': user_id,
        'date_from': date_from,
        'date_to': date_to,
        'search_query': search_query,
        'base_template': 'base_eb.html'
    }
    
    return render(request, 'eb_view/logs.html', context)

@role_required([1])
def user_management(request):
    users = User.objects.all().order_by('role', 'username')
    roles = UserRole.objects.all()
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'create_user':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            role_id = request.POST.get('role')
            
            if not all([username, email, password, role_id]):
                return render(request, 'eb_view/user_dashboard.html', {
                    'users': users, 
                    'roles': roles, 
                    'base_template': 'base_eb.html',
                    'error': 'All required fields must be filled'
                })
            
            if not email.endswith('@my.xu.edu.ph'):
                return render(request, 'eb_view/user_dashboard.html', {
                    'users': users, 
                    'roles': roles, 
                    'base_template': 'base_eb.html',
                    'error': 'Email must be from the @my.xu.edu.ph domain'
                })
            
            if User.objects.filter(username=username).exists():
                return render(request, 'eb_view/user_dashboard.html', {
                    'users': users, 
                    'roles': roles, 
                    'base_template': 'base_eb.html',
                    'error': 'Username already exists'
                })
            
            if User.objects.filter(email=email).exists():
                return render(request, 'eb_view/user_dashboard.html', {
                    'users': users, 
                    'roles': roles, 
                    'base_template': 'base_eb.html',
                    'error': 'Email already exists'
                })
            
            if len(password) < 8:
                return render(request, 'eb_view/user_dashboard.html', {
                    'users': users, 
                    'roles': roles, 
                    'base_template': 'base_eb.html',
                    'error': 'Password must be at least 8 characters long'
                })
            
            role = get_object_or_404(UserRole, role_id=role_id)
            user = User.objects.create(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role=role
            )
            
            ActivityLog.objects.create(
                user=get_object_or_404(User, pk=request.session.get('user_id')),
                action_type='User Creation',
                action_details=f'Created user {username} with role {role.role_name}'
            )          
            users = User.objects.all().order_by('role', 'username')
            
            return render(request, 'eb_view/user_dashboard.html', {
                'users': users, 
                'roles': roles, 
                'base_template': 'base_eb.html',
                'success': f'User {username} created successfully'
            })
        
        elif action == 'update_role':
            user_id = request.POST.get('user_id')
            new_role_id = request.POST.get('new_role_id')
            
            try:
                user = get_object_or_404(User, user_id=user_id)
                new_role = get_object_or_404(UserRole, role_id=new_role_id)
                
                old_role = user.role.role_name
                user.role = new_role
                user.save()
                
                ActivityLog.objects.create(
                    user=get_object_or_404(User, pk=request.session.get('user_id')),
                    action_type='Role Update',
                    action_details=f'Updated {user.username} role from {old_role} to {new_role.role_name}'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'Role updated successfully to {new_role.role_name}'
                })
            
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'User not found'
                })
            
            except UserRole.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'Role not found'
                })
            
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error updating role: {str(e)}'
                })
        
        elif action == 'delete_user':
            user_id = request.POST.get('user_id')
            
            try:
                user = get_object_or_404(User, user_id=user_id)
                username = user.username
                
                if user.user_id == request.session.get('user_id'):
                    return JsonResponse({
                        'success': False,
                        'message': 'You cannot delete your own account'
                    })
                
                user.delete()
                
                ActivityLog.objects.create(
                    user=get_object_or_404(User, pk=request.session.get('user_id')),
                    action_type='User Deletion',
                    action_details=f'Deleted user {username}'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'User {username} deleted successfully'
                })
            
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'User not found'
                })
            
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error deleting user: {str(e)}'
                })
    
    return render(request, 'eb_view/user_dashboard.html', {
        'users': users, 
        'roles': roles, 
        'base_template': 'base_eb.html'
    })