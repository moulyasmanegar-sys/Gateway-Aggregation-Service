"""
URL configuration for phishing_gateway project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path

def home(request):
    return HttpResponse("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Phishing Classification API</title>
            <style>
                body { font-family: sans-serif; max-width: 720px; margin: 4rem auto; padding: 0 1.5rem; }
                a { margin-right: 1rem; }
            </style>
        </head>
        <body>
            <h1>Phishing Classification API</h1>
            <p>The Django server is running successfully.</p>
            <a href="/api/emails/">Email API</a>
            <a href="/admin/">Admin panel</a>
        </body>
        </html>
    """)

urlpatterns = [
    path('', home, name='home'),
    path('admin/', admin.site.urls),
    path('api/', include('gateway.urls')),
]
