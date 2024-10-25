from django.urls import path 
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('register/',views.register_view,name='register'),
    path('login/',views.login_view,name='login'),
    path('logout/',views.logout_view,name='logout'),
    path('',views.dashboard_view,name='dashboard'),
    path('manual_rule_generator/',views.manual_rule_generator,name='manual_rule_generator'),
    path('auto_rule_gen/',views.auto_rule_gen,name='auto_rule_gen'),
    path('export_snort_rules/', views.export_snort_rules, name='export_snort_rules'),
    path('configure_snort/', views.configure_snort, name='configure_snort'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset/password_reset_form.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset/password_reset_complete.html'), name='password_reset_complete'),
    path('request-otp/', views.otp_request_view, name='request_otp'),
    path('verify-otp/', views.login_view, name='verify_otp'),
]