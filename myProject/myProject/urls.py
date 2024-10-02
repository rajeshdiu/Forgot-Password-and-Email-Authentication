from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path
from django.urls import path, include
from django.contrib.auth import views as auth_views
from myProject.views import *


urlpatterns = [
    path("admin/", admin.site.urls),
    path("logoutPage/", logoutPage,name="logoutPage"),
    path("", signupPage,name="signupPage"),
    path("signInPage/", signInPage,name="signInPage"),
    path("homePage/", homePage,name="homePage"),
    path("successPage/", successPage,name="successPage"),
    path("send_token/", send_token,name="send_token"),
    path('verify/<auth_token>',verify,name="verify"),
    path("send_token/", send_token,name="send_token"),
    path("error_page/", error_page,name="error_page"),
    path('reset_password/', password_reset_request, name='password_reset_request'),
    path('reset_password_confirm/<uidb64>/<token>/', reset_password_confirm, name='reset_password_confirm'),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
