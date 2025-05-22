#!/bin/bash
set -e

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Create default admin user if it doesn't exist
python manage.py shell -c "
from django.db import IntegrityError
try:
    from CRU.models import User, UserRole, Category
    
    # Create or update user roles with the correct IDs
    roles = [
        {'role_id': 1, 'role_name': 'Editorial Board'},
        {'role_id': 2, 'role_name': 'Copyreader'},
        {'role_id': 3, 'role_name': 'General Staff'}
    ]
    
    for role_data in roles:
        role, created = UserRole.objects.update_or_create(
            role_id=role_data['role_id'],
            defaults={'role_name': role_data['role_name']}
        )
        if created:
            print('Created ' + role_data['role_name'] + ' role')
        else:
            print('Updated ' + role_data['role_name'] + ' role')
    
    # Check if admin user exists
    if not User.objects.filter(email='admin@gmail.com').exists():
        print('Creating admin user...')
        # Get the Editorial Board role (role_id=1)
        editorial_role = UserRole.objects.get(role_id=1)
        admin_user = User(
            email='admin@gmail.com',
            username='admin',
            password='admin2425',  
            first_name='Admin',
            last_name='User',
            role=editorial_role
        )
        admin_user.save()
        print('Admin user created successfully')
    else:
        print('Admin user already exists')
        
    # Create default categories if they don't exist
    default_categories = [
        {'name': 'University News', 'description': 'News and updates about Xavier University - Ateneo de Cagayan'},
        {'name': 'Editorial', 'description': 'Opinion pieces from the editorial board'},
        {'name': 'Opinion', 'description': 'Opinion articles from contributors'},
        {'name': 'In Photos', 'description': 'Photo essays and visual stories'},
        {'name': 'Satire', 'description': 'Satirical and humorous content'}
    ]
    
    categories_created = 0
    for category_data in default_categories:
        category, created = Category.objects.get_or_create(
            name=category_data['name'],
            defaults={'description': category_data['description']}
        )
        if created:
            categories_created += 1
            
    if categories_created > 0:
        print('Created ' + str(categories_created) + ' new categories')
    else:
        print('All default categories already exist')
        
except ImportError as e:
    print('Error importing models: ' + str(e))
except IntegrityError as e:
    print('Error creating admin user or categories: ' + str(e))
except Exception as e:
    print('Unexpected error: ' + str(e))
"

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

case "$1" in
    dev)
        echo "Starting development server..."
        python manage.py runserver 0.0.0.0:8000
        ;;
    prod)
        echo "Starting production server..."
        gunicorn CRUPUB_NEWSPORTAL.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120
        ;;
    *)
        exec "$@"
        ;;
esac
