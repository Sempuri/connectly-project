<h1>Connectly</h1>

<p>
  <img alt="Django" src="https://img.shields.io/badge/Django-4.2-green">
  <img alt="DRF" src="https://img.shields.io/badge/DRF-3.14-red">
  <img alt="JWT" src="https://img.shields.io/badge/JWT-Authentication-blue">
</p>

<p>
  A social media API built with Django REST Framework featuring role-based access control, privacy settings, and optimized performance.
</p>

<h2>Features</h2>
<ul>
  <li><strong>Role-Based Access Control:</strong> Admin, user, and guest roles with appropriate permissions</li>
  <li><strong>Privacy Settings:</strong> Public and private post visibility</li>
  <li><strong>JWT Authentication:</strong> Secure token-based authentication</li>
  <li><strong>Performance Optimizations:</strong> Pagination and caching</li>
  <li><strong>Content Management:</strong> Full CRUD operations for posts, comments, and user interactions</li>
</ul>

<h2>Setup</h2>
<ol>
  <li>Clone the repository and create a virtual environment</li>
  <li>Install dependencies: <code>pip install -r requirements.txt</code></li>
  <li>Run migrations: <code>python manage.py migrate</code></li>
  <li>Create admin user:
    <pre><code>from posts.models import User
from django.contrib.auth.hashers import make_password

User.objects.create(
    username="admin",
    password=make_password("yourpassword"),
    email="admin@example.com",
    role="admin"
)
</code></pre>
  </li>
  <li>Start the server: <code>python manage.py runserver_plus --cert-file cert.pem --key-file key</code></li>
</ol>

<h2>Key Endpoints</h2>
<ul>
  <li><strong>Authentication:</strong> <code>/api/token/</code> (POST)</li>
  <li><strong>Users:</strong> <code>/posts/users/</code></li>
  <li><strong>Posts:</strong> <code>/posts/posts/</code></li>
  <li><strong>Comments:</strong> <code>/posts/comments/</code></li>
  <li><strong>Feed:</strong> <code>/posts/feed/</code></li>
</ul>

<h2>Authentication</h2>
<p>
  Send username and password to <code>/api/token/</code> to receive JWT tokens.  
  Include the access token in your request headers:
</p>
<pre><code>Authorization: Bearer YOUR_TOKEN</code></pre>

<h2>User Roles</h2>
<ul>
  <li><strong>Admin:</strong> Full system access</li>
  <li><strong>User:</strong> Create and manage own content</li>
  <li><strong>Guest:</strong> Read-only access to public content</li>
</ul>

<h2>Privacy</h2>
<p>
  Posts can be set as public (visible to all) or private (visible only to the author and admins).
</p>

<h2>Technologies</h2>
<ul>
  <li>Django + Django REST Framework</li>
  <li>JWT Authentication</li>
  <li>In-memory caching (configurable for Redis)</li>
  <li>Database query optimizations</li>
</ul>
