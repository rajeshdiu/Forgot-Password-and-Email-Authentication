from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from myApp.models import *
from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.contrib.auth.forms import PasswordResetForm
from myProject.forms import *
import uuid
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str


def signupPage(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        confirm_password = request.POST['confirm-password']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']
        user_type = request.POST.get('user_type')

        if password == confirm_password:
            if Custom_User.objects.filter(username=username).exists():
                messages.error(request, 'Username already taken.')
                return redirect('signupPage')
            elif Custom_User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered.')
                return redirect('signupPage')
            else:
                user = Custom_User.objects.create_user(
                username=username,
                email=email,
                password=password,
                user_type=user_type,
                )
                user.save()
                
                auth_token = str(uuid.uuid4())
                user.auth_token = auth_token
                
                print("Token Generated")
                user.save()  
                send_mail_after_registration(email , auth_token)
                return redirect('send_token')
                
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('signupPage')

    return render(request, 'signupPage.html')

# Signin View
def signInPage(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            user = Custom_User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome, {user.username}!')
                return redirect('homePage') 
            else:
                messages.error(request, 'Invalid credentials, please try again.')
                return redirect('signInPage')

        except Custom_User.DoesNotExist:
            messages.error(request, 'No user with this email exists.')
            return redirect('signInPage')

    return render(request, 'signInPage.html')


# Signout View
def logoutPage(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('signInPage')


@login_required
def homePage(request):
    
    return render(request,"homePage.html")


def send_token(request):
    
    return render(request,"send_token.html")

def successPage(request):
    
    return render(request,"successPage.html")

def error_page(request):
    return  render(request , 'error.html')



def verify(request,auth_token):
    
    print("Mail Verified")
    try:
        user_obj = Custom_User.objects.filter(auth_token = auth_token).first()

        if user_obj:
            if user_obj.is_verified:
                messages.success(request, 'Your account is already verified.')
                return redirect('signInPage')
            user_obj.is_verified = True
            user_obj.save()
            messages.success(request, 'Your account has been verified.')
            return redirect('signInPage')
        else:
            return redirect('signInPage')
    except Exception as e:
        print(e)
        return redirect('/')


def send_mail_after_registration(email,token):
    print("Mail Sent")
    subject = 'Your accounts need to be verified'
    message = f'Hi paste the link to verify your account http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message , email_from ,recipient_list )
    
    
#

def password_reset_request(request):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = Custom_User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                link = f"http://127.0.0.1:8000/reset_password_confirm/{uid}/{token}/"
                send_mail(
                    "Password Reset Request",
                    f"Hi, click the link to reset your password: {link}",
                    settings.EMAIL_HOST_USER,
                    [email],
                )
                messages.success(request, "Password reset link sent!")
                return redirect("password_reset_request")
            except Custom_User.DoesNotExist:
                messages.error(request, "User with this email does not exist.")
    else:
        form = PasswordResetForm()
    return render(request, "password_reset_request.html", {"form": form})




def reset_password_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = Custom_User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Custom_User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST['new_password']
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Your password has been reset successfully!')
            return redirect('signInPage')
        return render(request, 'reset_password_confirm.html', {'uid': uid, 'token': token})
    else:
        messages.error(request, 'Invalid password reset link')
        return redirect('password_reset_request')
