# Connectly API Project

A social media API built with Django REST Framework.

## Features

- User authentication (including Google OAuth)
- Create, view, edit, and delete posts
- Like and dislike posts
- Comment on posts
- Feed with sorting options and pagination

## API Endpoints

- `/users/` - View all users
- `/users/create/` - Create a user
- `/posts/` - View all posts
- `/posts/create/` - Create a post
- `/feed/` - View paginated posts feed
- `/comments/` - Create and view comments
- `/likes/` - Like posts
- `/dislikes/` - Dislike posts

## Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Start the server: `python manage.py runserver_plus --cert-file cert.pem --key-file key`
