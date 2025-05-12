from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from .models import *
import json
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt

def home(request):
    return render(request, 'public_view/home.html')

def login(request):
    return render(request, 'genadmin_view/login.html')

def pending_view(request):
    articles = Article.objects.filter(status=False).order_by('-created_at')
    return render(request, 'genadmin_view/pending.html', {
        'articles': articles
    })

def posted_view(request):
    if request.method == "POST":
        pass
    articles = Article.objects.filter(status=True).order_by('-published_at')
    return render(request, 'genadmin_view/posted.html', {
        'articles': articles
    })

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
    return render(request, 'genadmin_view/create.html', {'categories': categories})

def edit_profile(request):
    return render(request, 'genadmin_view/edit_profile.html')

def logs(request):
    return render(request, 'eb_view/logs.html')

def user_management(request):
    return render(request, 'eb_view/user_dashboard.html')

def about(request):
    return render(request, 'public_view/about.html')

def search(request):    
    return render(request, 'public_view/search.html')