# Generated by Django 5.2.1 on 2025-05-21 14:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CRU', '0002_featureimage_image_alter_featureimage_article_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='article',
            name='author',
        ),
        migrations.AddField(
            model_name='article',
            name='articlecreatedby',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='CRU.user'),
        ),
        migrations.AddField(
            model_name='article',
            name='author_name',
            field=models.CharField(default='', max_length=255),
        ),
    ]
