from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from .models import *
import json
from datetime import datetime

def home(request):
    return render(request, 'public_view/home.html')

def login(request):
    return render(request, 'genadmin_view/login.html')

def pending_view(request):
    articles = Article.objects.all()
    return render(request, 'genadmin_view/pending.html', {
        'articles': articles
    })

def posted_view(request):
    if request.method == "POST":
        pass  # Add any required POST logic here
    articles = Article.objects.all()
    return render(request, 'genadmin_view/posted.html', {
        'articles': articles
    })

def create_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body).get('data', {})

            title = data.get('title')
            content = data.get('content')
            category_id = data.get('category')
            author_id = data.get('author')
            img = data.get('image')
            journalist = data.get('journalist')

            new_article = Article.objects.create(
                title=title,
                content=content,
                author=User.objects.get(pk=author_id),
                status=False,
                CopyReader_Status=False,
                Editorial_Status=False,
                category=Category.objects.get(pk=category_id),
                created_at=datetime.now()
            )

            if img:
                FeatureImage.objects.create(
                    article=new_article,
                    image_url=img,
                    photo_journalist=journalist
                )

            return JsonResponse({'message': 'Success', 'article_id': new_article.article_id})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
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