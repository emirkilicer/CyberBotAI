from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

urlpatterns = [
    path("", views.home_view, name="home"),
    path("signup/", views.signup_view, name="signup"),
    # The account to enroll is taken from the server-side session. It must
    # never be supplied by the client (removed: <str:username>).
    path("setup-2fa/", views.setup_2fa_view, name="setup_2fa"),
    path("recovery-codes/", views.recovery_codes_view, name="recovery_codes"),
    path("login/", views.login_view, name="login"),
    path("verify-2fa/", views.verify_2fa_view, name="verify_2fa"),
    path("logout/", views.logout_view, name="logout"),
    path("profile/", views.profile_view, name="profile"),
    path("profile/recovery-codes/", views.regenerate_recovery_codes_view, name="regenerate_recovery_codes"),
    path("profile/delete/", views.delete_account_view, name="delete_account"),
    path("api/chat/", views.api_chat_view, name="api_chat"),

    # Email verification
    path("verify-email/sent/", views.verify_email_sent_view, name="verify_email_sent"),
    path("verify-email/resend/", views.resend_email_verification_view, name="resend_email_verification"),
    path("verify-email/<str:token>/", views.verify_email_view, name="verify_email"),

    # Password reset (Django's secure token flow, still followed by 2FA)
    path(
        "password-reset/",
        views.RateLimitedPasswordResetView.as_view(
            template_name="password_reset_form.html",
            email_template_name="password_reset_email.html",
            subject_template_name="password_reset_subject.txt",
            success_url=reverse_lazy("password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="password_reset_done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="password_reset_confirm.html",
            success_url=reverse_lazy("password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
]
