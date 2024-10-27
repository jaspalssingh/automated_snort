from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout
from .middlewares import auth, guest
import csv,os
import random
from django.core.mail import send_mail
from django.contrib import messages
from django import forms
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from .forms import CustomUserCreationForm  # Import the custom form
from django.http import JsonResponse

def generate_otp():
    return str(random.randint(100000, 999999))

class CustomUserCreationForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True, help_text='First name')
    last_name = forms.CharField(max_length=30, required=True, help_text='Last name')

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

def send_otp_email(email, otp):
    subject = "Your OTP for Authentication"
    message = f"Your OTP is {otp}. Please use this to verify your account."
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, email_from, [email])

def otp_request_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = generate_otp()
        request.session.set_expiry(3000)  # Set session expiry to 5 minutes for OTP

        # Store the OTP and email in session (in real-world apps, store it securely)
        request.session['otp'] = otp
        request.session['email'] = email
        
        # Send the OTP via email
        send_otp_email(email, otp)
        messages.success(request, 'OTP has been sent to your email. Please check your inbox.')

        return redirect('verify_otp')  # Redirect to the OTP verification page

    return render(request, 'otp/otp_request.html')

from django.contrib.auth import get_user_model


@auth
def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.first_name = form.cleaned_data.get('first_name')
            user.last_name = form.cleaned_data.get('last_name')
            user.save()
            login(request, user)
            return redirect('dashboard')
    else:
        form = CustomUserCreationForm()
        print(form)


    return render(request, 'auth/register.html', {'form': form})


@guest
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    otp_required = False  # Flag to track whether OTP is needed

    if request.method == 'POST':
        # If OTP form is submitted
        if 'otp' in request.POST:
            input_otp = request.POST.get('otp')
            session_otp = request.session.get('otp')

            if input_otp == session_otp:
                user_id = request.session.get('user_id')
                User = get_user_model()
                user = User.objects.get(id=user_id)

                # Log the user in and clear OTP session variables
                login(request, user)
                request.session.pop('otp', None)
                request.session.pop('user_id', None)

                messages.success(request, 'OTP verified successfully. Welcome to your dashboard.')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                otp_required = True

        # If username/password form is submitted
        else:
            form = AuthenticationForm(request, data=request.POST)

            if form.is_valid():
                user = form.get_user()

                # Generate OTP, send it via email, and store in session
                otp = generate_otp()
                request.session['otp'] = otp
                request.session['user_id'] = user.id
                send_otp_email(user.email, otp)

                otp_required = True  # Now OTP is required

    else:
        form = AuthenticationForm()

    return render(request, 'auth/login.html', {
        'form': form,
        'otp_required': otp_required  # Pass this to the template
    })

def dashboard_view(request):
    return render(request, 'dashboard.html')

@auth
def logout_view(request):
    logout(request)
    return redirect('login')
@auth
def export_snort_rules(request):
    if request.method == 'POST':
        snort_rules = request.POST.get('snort_rules', '')

        # Create the HTTP response with the rules as a text file
        response = HttpResponse(snort_rules, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="snort_rules.rules"'
        
        return response

    return redirect('auto_rule_gen')


SNORT_RULES_PATH = '/etc/snort/rules/snort_rule.rules'  # Update this to the actual path if needed

# Function to read the last used SID from a file
def get_last_sid(file_path='last_sid.txt'):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return int(file.read().strip())
    return 100000  # Default initial SID if the file does not exist

# Function to update the last used SID in the file
def update_last_sid(sid, file_path='last_sid.txt'):
    with open(file_path, 'w') as file:
        file.write(str(sid))

# Main function to generate Snort rules from the CSV file (does not save to file yet)
def generate_snort_rule(csv_file):
    snort_rules = []  # Initialize an empty list to hold the generated rules

    try:
        last_sid = get_last_sid()  # Get the last used SID
        
        with open(csv_file, newline='', encoding='utf-8') as file:  # Open the CSV file
            csv_reader = csv.DictReader(file)  # Read the CSV file as a dictionary
            for row in csv_reader:
                ip = row.get("IP", "any").strip()
                port = row.get("Port", "any").strip()  # Get the Port, default to 'any'
                cve = row.get("CVEs", "").strip()
                severity = row.get("Severity", "low").strip()
                nvt_name = row.get("NVT Name", "NVT Unknown").strip()

                # Customize the rule message and content based on the CSV information
                rule_message = f"OpenVAS Alert: {severity} - {nvt_name}"
                #AI auth 
                rule_content = f"USER {cve[:255]}"  # Limiting CVE content length for Snort compatibility

                # Increment the SID and generate a Snort rule
                last_sid += 1  # Ensure a unique SID is generated
                rule = f'alert tcp any any -> {ip} {port} (msg:"{rule_message}"; content:"{rule_content}"; sid:{last_sid};)\n'

                # Append the rule to the list
                snort_rules.append(rule)

        # Update the last SID in the file
        update_last_sid(last_sid)

        # After generating the rules, delete the CSV file
        os.remove(csv_file)
        print(f"File {csv_file} deleted successfully.")

    except Exception as e:
        print(f"Error processing file {csv_file}: {e}")

    # Return the generated rules as a string for display or later use
    return "\n".join(snort_rules)

# Django view to handle file upload and display Snort rules
@auth
def auto_rule_gen(request):
    if request.method == 'POST' and request.FILES.get('csv_file'):
        # Get the uploaded file and the name from the form
        csv_file = request.FILES['csv_file']
        name = request.POST['name']
        
        # Save the uploaded file to a temporary location
        fs = FileSystemStorage()
        filename = fs.save(csv_file.name, csv_file)
        file_path = fs.path(filename)
        
        # Generate Snort rules from the uploaded CSV file
        snort_rules = generate_snort_rule(file_path)
        
        # Store the results in the session and redirect to avoid POST persistence
        request.session['snort_rules'] = snort_rules
        request.session['name'] = name
        
        # Redirect after POST to prevent form resubmission on refresh
        return redirect('auto_rule_gen')  # Assuming 'auto_rule_gen' is the name of this URL

    # Handle GET requests (rendering the page initially or after redirect)
    snort_rules = request.session.pop('snort_rules', None)  # Get and remove from session
    name = request.session.pop('name', None)  # Get and remove from session
    
    return render(request, 'auth/auto_rule_gen.html', {
        'snort_rules': snort_rules,
        'name': name
    })

# Configure Snort view - Save (merge) rules to the Snort file when called
def configure_snort(request):
    if request.method == 'POST':
        snort_rules = request.POST.get('snort_rules', '')
        name = request.POST.get('name', '')

        if snort_rules:
            try:
                with open(SNORT_RULES_PATH, 'a' if os.path.exists(SNORT_RULES_PATH) else 'w') as rule_file:
                    rule_file.write(snort_rules)
                
                # Return success message as JSON
                return JsonResponse({
                    'status': 'success',
                    'message': f"Snort rules configured for {name} and merged into {SNORT_RULES_PATH}.",
                    'snort_rules': snort_rules
                })

            except Exception as e:
                # Return error message as JSON
                return JsonResponse({
                    'status': 'error',
                    'message': f"Failed to configure Snort rules: {e}"
                })

        return JsonResponse({'status': 'error', 'message': "No Snort rules were provided."})
    
    return JsonResponse({'status': 'error', 'message': "Invalid request method."})


def manual_rule_generator(request):
    return render(request, 'auth/manual_rule_generator.html')
