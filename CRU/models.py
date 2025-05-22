from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
import re

class UserRole(models.Model):
   role_id = models.AutoField(primary_key=True)
   role_name = models.CharField(max_length=50)
   
   def __str__(self):
       return self.role_name

class Category(models.Model):
   category_id = models.AutoField(primary_key=True)
   name = models.CharField(max_length=100)
   description = models.TextField()
   
   def __str__(self):
       return self.name

class User(models.Model):
   user_id = models.AutoField(primary_key=True)
   username = models.CharField(max_length=150, unique=True)
   email = models.EmailField(max_length=254, unique=True)
   password = models.CharField(max_length=128)
   first_name = models.CharField(max_length=30, blank=True)
   last_name = models.CharField(max_length=30, blank=True)
   date_joined = models.DateTimeField(auto_now_add=True)
   role = models.ForeignKey(UserRole, on_delete=models.CASCADE)
   
   def __str__(self):
       return self.username
   
   def clean(self):
       if self.email and not self.email.endswith('@my.xu.edu.ph'):
           raise ValidationError('Email must be from the @my.xu.edu.ph domain')
       
   def save(self, *args, **kwargs):
       self.clean()
       if self.password and not self.password.startswith('pbkdf2_sha256$'):
           self.password = make_password(self.password)
       super().save(*args, **kwargs)
       
   def check_password(self, raw_password):
       return check_password(raw_password, self.password)

class Article(models.Model):
   article_id = models.AutoField(primary_key=True)
   title = models.CharField(max_length=255)
   content = models.TextField()
   articlecreatedby = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
   author_name = models.CharField(max_length=255, default='')
   status = models.BooleanField(default=False)
   CopyReader_Status = models.BooleanField(default=False)
   Editorial_Status = models.BooleanField(default=False)
   category = models.ForeignKey(Category, on_delete=models.CASCADE)
   created_at = models.DateTimeField(auto_now_add=True)
   updated_at = models.DateTimeField(null=True, blank=True)
   published_at = models.DateTimeField(null=True, blank=True)
   
   def __str__(self):
       return self.title

class FeatureImage(models.Model):
   image_id = models.AutoField(primary_key=True)
   article = models.ForeignKey(Article, on_delete=models.CASCADE, related_name='feature_images')
   image = models.ImageField(upload_to='feature_images/', null=True, blank=True)
   image_url = models.URLField(max_length=255, null=True, blank=True) 
   photo_journalist = models.CharField(max_length=255)
   
   def __str__(self):
       return f"Image for {self.article.title}"

class ActivityLog(models.Model):
   log_id = models.AutoField(primary_key=True)
   user = models.ForeignKey(User, on_delete=models.CASCADE)
   action_type = models.CharField(max_length=50)
   action_details = models.CharField(max_length=255)
   timestamp = models.DateTimeField(auto_now_add=True)
   
   def __str__(self):
       return f"{self.user.username} - {self.action_type} at {self.timestamp}"