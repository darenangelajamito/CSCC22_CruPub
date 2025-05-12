from django.shortcuts import render, HttpResponse, redirect
from django.http import JsonResponse
from .models import *
import json
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt
from functools import wraps

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.session.get('user_id'):
                return redirect('CRU:Login')
            
            try:
                user = User.objects.get(pk=request.session.get('user_id'))
                if user.role.role_id in allowed_roles:
                    return view_func(request, *args, **kwargs)
                else:
                    return redirect('CRU:Home')
            except User.DoesNotExist:
                return redirect('CRU:Login')
        return wrapper
    return decorator

def home(request):
    return render(request, 'public_view/home.html')

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                request.session['user_id'] = user.user_id
                request.session['role_id'] = user.role.role_id
                request.session['username'] = user.username
                
                ActivityLog.objects.create(
                    user=user,
                    action_type='Login',
                    action_details=f'User logged in'
                )
                
                if user.role.role_id == 1:  # Editorial Board
                    return redirect('CRU:DashboardPending')
                else:  # Copyreader or General Staff
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
                action_details=f'User logged out'
            )
        except User.DoesNotExist:
            pass
    
    request.session.flush()
    return redirect('CRU:Login')

@role_required([1, 2, 3])  # All roles can access
def pending_view(request):
    articles = Article.objects.filter(status=False).order_by('-created_at')
    user_role = request.session.get('role_id')
    
    context = {'articles': articles}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'genadmin_view/pending.html', context)

@role_required([1, 2, 3])  # All roles can access
def posted_view(request):
    if request.method == "POST":
        pass
    articles = Article.objects.filter(status=True).order_by('-published_at')
    user_role = request.session.get('role_id')
    
    context = {'articles': articles}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'genadmin_view/posted.html', context)

@role_required([1, 2, 3])  # All roles can access
def create_view(request):
    if request.method == 'POST':
        try:
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format'}, status=400)

            required_fields = ['title', 'content', 'category', 'author', 'image', 'journalist']
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return JsonResponse(
                    {'error': f'Missing required fields: {", ".join(missing_fields)}'}, 
                    status=400
                )

            if not isinstance(data.get('title'), str) or not isinstance(data.get('content'), str):
                return JsonResponse({'error': 'Invalid data type: title and content must be strings'}, status=400)
            if not isinstance(data.get('category'), (int, str)) or not isinstance(data.get('author'), (int, str)):
                return JsonResponse({'error': 'Invalid data type: category and author must be integers'}, status=400)
            if not isinstance(data.get('image'), str) or not isinstance(data.get('journalist'), str):
                return JsonResponse({'error': 'Invalid data type: image and journalist must be strings'}, status=400)

            try:
                author = User.objects.get(pk=data['author'])
            except User.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=400)

            try:
                category = Category.objects.get(pk=data['category'])
            except Category.DoesNotExist:
                return JsonResponse({'error': 'Category not found'}, status=400)

            try:
                new_article = Article.objects.create(
                    title=data['title'],
                    content=data['content'],
                    author=author,
                    status=False,
                    CopyReader_Status=False,
                    Editorial_Status=False,
                    category=category,
                    created_at=datetime.now(),
                    updated_at=None,
                    published_at=None
                )

                FeatureImage.objects.create(
                    article=new_article,
                    image_url=data['image'],
                    photo_journalist=data['journalist']
                )

                return JsonResponse({'message': 'Success', 'article_id': new_article.article_id})

            except Exception as e:
                return JsonResponse({'error': f'Error creating article: {str(e)}'}, status=500)

        except Exception as e:
            return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)

    categories = Category.objects.all()
    user_role = request.session.get('role_id')
    
    context = {'categories': categories}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'genadmin_view/create.html', context)

@role_required([1, 2, 3])  # All roles can access
def edit_profile(request):
    user = User.objects.get(pk=request.session.get('user_id'))
    if request.method == 'POST':
        try:
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            user.email = request.POST.get('email')
            user.save()
            return render(request, 'genadmin_view/edit_profile.html', {'success': 'Profile updated successfully'})
        except Exception as e:
            return render(request, 'genadmin_view/edit_profile.html', {'error': 'Error updating profile'})
    
    user_role = request.session.get('role_id')
    
    context = {'user': user}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'genadmin_view/edit_profile.html', context)

@role_required([1])  # Only Editorial Board can access
def logs(request):
    logs = ActivityLog.objects.all().order_by('-timestamp')
    user_role = request.session.get('role_id')
    
    context = {'logs': logs}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'eb_view/logs.html', context)

@role_required([1])  # Only Editorial Board can access
def user_management(request):
    users = User.objects.all().order_by('role', 'username')
    roles = UserRole.objects.all()
    user_role = request.session.get('role_id')
    
    context = {'users': users, 'roles': roles}
    
    if user_role == 1:  
        context['base_template'] = 'base_eb.html'
    else:  
        context['base_template'] = 'base_noneb.html'
    
    return render(request, 'eb_view/user_dashboard.html', context)

def about(request):
    return render(request, 'public_view/about.html')

def search(request):    
    return render(request, 'public_view/search.html')