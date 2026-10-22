"""CYBERBOT authentication and chat views.

Security model:
  * A user is only logged in after a valid TOTP code (or after enrolling one).
  * Pending authentication state lives in a short-lived server-side session,
    never in a URL or a hidden form field.
  * All credential verification is rate limited and audited.
  * The chat endpoint is session authenticated, CSRF protected and throttled.
"""

from __future__ import annotations

import json
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from . import ai, ai_safety
from .forms import ProfileUpdateForm, RegisterForm
from .middleware import SESSION_2FA_KEY
from .models import UserTwoFactor
from .services import audit, email_verification, enrollment, ratelimit, recovery
from .services import totp as totp_service

logger = logging.getLogger(__name__)

_PENDING_USER_KEY = "pending_2fa_user_id"
_PENDING_TS_KEY = "pending_2fa_started_at"
_PENDING_SIGNUP_KEY = "pending_2fa_signup"
_ENROLLMENT_HASH_KEY = "enrollment_token_hash"

_GENERIC_LOGIN_ERROR = "Invalid username or password!"
_GENERIC_2FA_ERROR = "Invalid or expired code. Please try again."
_RATE_LIMIT_ERROR = "Too many attempts. Please wait a few minutes and try again."


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
def _start_pending_authentication(request, user, *, signup: bool = False) -> None:
    request.session.cycle_key()
    request.session.pop(SESSION_2FA_KEY, None)
    request.session.pop("auth_2fa_at", None)
    request.session.pop(_ENROLLMENT_HASH_KEY, None)
    request.session[_PENDING_USER_KEY] = user.pk
    request.session[_PENDING_TS_KEY] = timezone.now().timestamp()
    request.session[_PENDING_SIGNUP_KEY] = signup


def _clear_pending_authentication(request) -> None:
    request.session.pop(_PENDING_USER_KEY, None)
    request.session.pop(_PENDING_TS_KEY, None)
    request.session.pop(_PENDING_SIGNUP_KEY, None)
    request.session.pop(_ENROLLMENT_HASH_KEY, None)


def _mark_session_verified(request) -> None:
    request.session[SESSION_2FA_KEY] = True
    request.session["auth_2fa_at"] = timezone.now().timestamp()


def _pending_user(request):
    user_id = request.session.get(_PENDING_USER_KEY)
    started_at = request.session.get(_PENDING_TS_KEY)
    if not user_id or not started_at:
        return None

    try:
        age = timezone.now().timestamp() - float(started_at)
    except (TypeError, ValueError):
        _clear_pending_authentication(request)
        return None

    if age < 0 or age > settings.TWO_FACTOR_PENDING_TIMEOUT:
        _clear_pending_authentication(request)
        return None

    user = User.objects.filter(pk=user_id, is_active=True).first()
    if user is None:
        _clear_pending_authentication(request)
    return user


def _get_two_factor(user) -> UserTwoFactor:
    two_factor, _ = UserTwoFactor.objects.get_or_create(user=user)
    return two_factor


# ---------------------------------------------------------------------------
# Two-factor throttling
# ---------------------------------------------------------------------------
def _is_2fa_locked(user, request) -> bool:
    ip = ratelimit.client_ip(request)
    user_ip = f"{user.pk}:{ip}"
    return (
        ratelimit.is_locked("2fa:user_ip", user_ip)
        or ratelimit.is_locked("2fa:ip", ip)
        or ratelimit.is_locked("2fa:user_global", user.pk)
    )


def _record_2fa_failure(user, request) -> None:
    ip = ratelimit.client_ip(request)
    user_ip = f"{user.pk}:{ip}"
    limit = settings.TWO_FACTOR_MAX_ATTEMPTS
    lockout = settings.TWO_FACTOR_LOCKOUT_SECONDS
    # Strict per user+IP limit avoids a single attacker locking an account
    # globally. The global username counter is a higher distributed-attack
    # backstop, not the primary control.
    ratelimit.record_failure(
        "2fa:user_ip", user_ip, limit=limit, window=lockout, lockout=lockout
    )
    ratelimit.record_failure(
        "2fa:ip",
        ip,
        limit=limit * 4,
        window=lockout,
        lockout=lockout,
    )
    ratelimit.record_failure(
        "2fa:user_global",
        user.pk,
        limit=limit * 10,
        window=lockout,
        lockout=lockout,
    )


def _clear_2fa_failures(user, request) -> None:
    ip = ratelimit.client_ip(request)
    ratelimit.clear_failures("2fa:user_ip", f"{user.pk}:{ip}")
    ratelimit.clear_failures("2fa:ip", ip)
    ratelimit.clear_failures("2fa:user_global", user.pk)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def home_view(request):
    return render(request, "index.html")


@never_cache
@require_http_methods(["GET", "POST"])
def signup_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    form = RegisterForm(request.POST or None)
    status = 200

    if request.method == "POST":
        ip = ratelimit.client_ip(request)
        if not ratelimit.allow(
            "signup:ip",
            ip,
            limit=settings.SIGNUP_RATE_LIMIT_PER_HOUR,
            window=60 * 60,
        ):
            audit.log_event("signup_rate_limited", request=request, username=request.POST.get("username"))
            return render(
                request,
                "signup.html",
                {"form": form, "error": _RATE_LIMIT_ERROR},
                status=429,
            )

        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data["password"])
            user.save()

            two_factor = _get_two_factor(user)
            two_factor.set_otp_secret(totp_service.generate_secret())
            two_factor.save(update_fields=["otp_secret", "updated_at"])

            # Do not log in yet: the account becomes usable only after the
            # user proves possession of the TOTP secret.
            _start_pending_authentication(request, user, signup=True)
            try:
                email_verification.send_verification_email(request, user)
            except Exception as exc:
                logger.error("Failed to send signup verification email (%s)", type(exc).__name__)
            audit.log_event("signup", request=request, user=user)
            if settings.REQUIRE_EMAIL_VERIFICATION:
                return redirect("verify_email_sent")
            return redirect("setup_2fa")

    return render(request, "signup.html", {"form": form}, status=status)


@never_cache
@require_http_methods(["GET", "POST"])
def setup_2fa_view(request):
    if request.user.is_authenticated:
        user = request.user
    else:
        user = _pending_user(request)

    if user is None:
        _clear_pending_authentication(request)
        return redirect("login")

    two_factor = _get_two_factor(user)

    # Never expose the QR/secret of an account that is already protected.
    if two_factor.is_enabled and two_factor.is_configured:
        if request.user.is_authenticated:
            return redirect("profile")
        return redirect("verify_2fa")

    # A corrupt/legacy row with is_enabled=True but no secret must be reset.
    if two_factor.is_enabled and not two_factor.is_configured:
        two_factor.is_enabled = False
        two_factor.last_used_step = None
        two_factor.save(update_fields=["is_enabled", "last_used_step", "updated_at"])

    if settings.REQUIRE_EMAIL_VERIFICATION and not email_verification.is_verified(user):
        return redirect("verify_email_sent")

    # Signups created in this session may enroll immediately. Existing
    # accounts (including CLI-created admins) need an out-of-band token, so a
    # stolen password cannot enroll the attacker's authenticator.
    is_signup = bool(request.session.get(_PENDING_SIGNUP_KEY))
    enrollment_record = None
    enrollment_error = None

    if not is_signup:
        raw_enrollment = request.POST.get("token") or request.GET.get("token")
        if raw_enrollment:
            enrollment_record = enrollment.validate_token(user, raw_enrollment)
            if enrollment_record is None:
                enrollment_error = "Invalid or expired enrollment token."
            else:
                request.session[_ENROLLMENT_HASH_KEY] = enrollment_record.token_hash
        else:
            enrollment_record = enrollment.validate_token_hash(
                user, request.session.get(_ENROLLMENT_HASH_KEY)
            )
            if enrollment_record is None:
                enrollment_error = "An enrollment token is required for this account."

        if enrollment_record is None:
            return render(
                request,
                "setup_2fa.html",
                {
                    "needs_enrollment": True,
                    "username": user.username,
                    "error": enrollment_error,
                },
                status=403 if request.method == "POST" else 200,
            )

    if not two_factor.is_configured:
        two_factor.set_otp_secret(totp_service.generate_secret())
        two_factor.save(update_fields=["otp_secret", "updated_at"])

    error = None
    status = 200
    otp_code = request.POST.get("otp_code") if request.method == "POST" else None

    if request.method == "POST" and otp_code is not None:
        if _is_2fa_locked(user, request):
            error = _RATE_LIMIT_ERROR
            status = 429
            audit.log_event("2fa_setup_locked", request=request, user=user)
        elif totp_service.verify_code(two_factor, otp_code):
            two_factor.is_enabled = True
            two_factor.save(update_fields=["is_enabled", "updated_at"])
            enrollment.consume_token(enrollment_record)
            request.session.pop(_ENROLLMENT_HASH_KEY, None)
            _clear_2fa_failures(user, request)
            _clear_pending_authentication(request)
            codes = recovery.generate_codes(user)
            request.session["new_recovery_codes"] = codes
            login(request, user)
            _mark_session_verified(request)
            audit.log_event("2fa_enabled", request=request, user=user)
            return redirect("recovery_codes")
        else:
            _record_2fa_failure(user, request)
            audit.log_event("2fa_setup_failed", request=request, user=user)
            error = _GENERIC_2FA_ERROR

    secret = two_factor.get_otp_secret()
    uri = totp_service.provisioning_uri(user, secret)
    context = {
        "qr_code": totp_service.qr_data_uri(uri),
        "username": user.username,
        "error": error,
        "needs_enrollment": False,
    }
    return render(request, "setup_2fa.html", context, status=status)


@never_cache
@login_required(login_url="login")
def recovery_codes_view(request):
    codes = request.session.pop("new_recovery_codes", None)
    return render(request, "recovery_codes.html", {"codes": codes})


@never_cache
def verify_email_sent_view(request):
    pending = _pending_user(request)
    email = pending.email if pending else ""
    return render(request, "verify_email_sent.html", {"email": email})


@never_cache
def verify_email_view(request, token):
    user = email_verification.verify_token(token)
    if user is None:
        return render(
            request,
            "verify_email_sent.html",
            {"error": "This verification link is invalid or has expired."},
            status=400,
        )

    audit.log_event("email_verified", request=request, user=user)
    messages.success(request, "Email verified. Continue with two-factor authentication.")

    pending = _pending_user(request)
    if pending is not None and pending.pk == user.pk:
        two_factor = _get_two_factor(user)
        if two_factor.is_enabled and two_factor.is_configured:
            return redirect("verify_2fa")
        return redirect("setup_2fa")
    return redirect("login")


@never_cache
@require_POST
def resend_email_verification_view(request):
    ip = ratelimit.client_ip(request)
    if not ratelimit.allow("email_verify:ip", ip, limit=5, window=60 * 60):
        return render(
            request,
            "verify_email_sent.html",
            {"error": _RATE_LIMIT_ERROR},
            status=429,
        )

    email = (request.POST.get("email") or "").strip()
    if request.user.is_authenticated and request.user.email:
        email = request.user.email

    user = User.objects.filter(email__iexact=email, is_active=True).first()
    if user is not None and not email_verification.is_verified(user):
        try:
            email_verification.send_verification_email(request, user)
        except Exception as exc:
            logger.error("Failed to resend verification email (%s)", type(exc).__name__)

    # Same response whether or not the address exists (no enumeration).
    return render(
        request,
        "verify_email_sent.html",
        {"email": email, "sent": True},
    )


class RateLimitedPasswordResetView(auth_views.PasswordResetView):
    """Django's reset view with an IP throttle to prevent email bombing."""

    def post(self, request, *args, **kwargs):
        ip = ratelimit.client_ip(request)
        if not ratelimit.allow("password_reset:ip", ip, limit=5, window=60 * 60):
            audit.log_event("password_reset_rate_limited", request=request)
            return HttpResponse(
                "Too many password reset requests. Try again later.",
                status=429,
                content_type="text/plain",
            )
        return super().post(request, *args, **kwargs)


@never_cache
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    error = None
    status = 200

    if request.method == "POST":
        _clear_pending_authentication(request)
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        ip = ratelimit.client_ip(request)
        user_key = username.lower()
        user_ip_key = f"{user_key}:{ip}"

        if (
            ratelimit.is_locked("login:user_ip", user_ip_key)
            or ratelimit.is_locked("login:ip", ip)
            or ratelimit.is_locked("login:user_global", user_key)
        ):
            audit.log_event("login_locked", request=request, username=username)
            return render(
                request,
                "login.html",
                {"error": _RATE_LIMIT_ERROR},
                status=429,
            )

        user = authenticate(request, username=username, password=password)
        if user is not None:
            ratelimit.clear_failures("login:user_ip", user_ip_key)
            ratelimit.clear_failures("login:ip", ip)
            ratelimit.clear_failures("login:user_global", user_key)
            _start_pending_authentication(request, user)
            two_factor = _get_two_factor(user)
            audit.log_event("password_ok", request=request, user=user)

            if settings.REQUIRE_EMAIL_VERIFICATION and not email_verification.is_verified(user):
                try:
                    email_verification.send_verification_email(request, user)
                except Exception as exc:
                    logger.error("Failed to send login verification email (%s)", type(exc).__name__)
                audit.log_event("email_verification_required", request=request, user=user)
                return redirect("verify_email_sent")

            if two_factor.is_enabled and two_factor.is_configured:
                return redirect("verify_2fa")
            return redirect("setup_2fa")

        ratelimit.record_failure(
            "login:user_ip",
            user_ip_key,
            limit=settings.LOGIN_ATTEMPT_LIMIT,
            window=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
            lockout=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
        )
        ratelimit.record_failure(
            "login:ip",
            ip,
            limit=settings.LOGIN_ATTEMPT_LIMIT * 3,
            window=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
            lockout=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
        )
        ratelimit.record_failure(
            "login:user_global",
            user_key,
            limit=settings.LOGIN_ATTEMPT_LIMIT * 5,
            window=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
            lockout=settings.LOGIN_ATTEMPT_WINDOW_SECONDS,
        )
        audit.log_event("login_failed", request=request, username=username)
        error = _GENERIC_LOGIN_ERROR

    return render(request, "login.html", {"error": error}, status=status)


@never_cache
@require_http_methods(["GET", "POST"])
def verify_2fa_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    user = _pending_user(request)
    if user is None:
        return redirect("login")

    two_factor = _get_two_factor(user)
    if not two_factor.is_enabled or not two_factor.is_configured:
        return redirect("setup_2fa")

    error = None
    status = 200

    if request.method == "POST":
        if _is_2fa_locked(user, request):
            error = _RATE_LIMIT_ERROR
            status = 429
            audit.log_event("2fa_login_locked", request=request, user=user)
        else:
            recovery_attempt = "recovery_code" in request.POST
            if recovery_attempt:
                valid = recovery.verify_code(user, request.POST.get("recovery_code", ""))
            else:
                valid = totp_service.verify_code(two_factor, request.POST.get("otp_code"))

            if valid:
                _clear_2fa_failures(user, request)
                _clear_pending_authentication(request)
                login(request, user)
                _mark_session_verified(request)
                audit.log_event(
                    "recovery_login" if recovery_attempt else "login_success",
                    request=request,
                    user=user,
                )
                return redirect("home")

            _record_2fa_failure(user, request)
            audit.log_event("2fa_login_failed", request=request, user=user)
            error = _GENERIC_2FA_ERROR

    return render(request, "verify_2fa.html", {"error": error}, status=status)


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        audit.log_event("logout", request=request, user=request.user)
    logout(request)
    return redirect("home")


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
@never_cache
@login_required(login_url="login")
@require_http_methods(["GET", "POST"])
def profile_view(request):
    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            audit.log_event("profile_updated", request=request, user=request.user)
            return redirect("profile")
    else:
        form = ProfileUpdateForm(instance=request.user)

    return render(request, "profile.html", {"form": form})


@never_cache
@login_required(login_url="login")
@require_POST
def regenerate_recovery_codes_view(request):
    user = request.user
    two_factor = _get_two_factor(user)

    def _render_error(message, status=400):
        return render(
            request,
            "profile.html",
            {
                "form": ProfileUpdateForm(instance=user),
                "recovery_error": message,
            },
            status=status,
        )

    if not two_factor.is_enabled or not two_factor.is_configured:
        return redirect("setup_2fa")

    if _is_2fa_locked(user, request):
        return _render_error(_RATE_LIMIT_ERROR, status=429)

    if not totp_service.verify_code(two_factor, request.POST.get("otp_code")):
        _record_2fa_failure(user, request)
        audit.log_event("recovery_codes_regenerate_failed", request=request, user=user)
        return _render_error("Invalid 2FA code. Recovery codes were not changed.")

    _clear_2fa_failures(user, request)
    codes = recovery.generate_codes(user)
    request.session["new_recovery_codes"] = codes
    audit.log_event("recovery_codes_regenerated", request=request, user=user)
    return redirect("recovery_codes")


@never_cache
@login_required(login_url="login")
@require_POST
def delete_account_view(request):
    user = request.user

    def _render_error(message, status=400):
        return render(
            request,
            "profile.html",
            {
                "form": ProfileUpdateForm(instance=user),
                "delete_error": message,
            },
            status=status,
        )

    two_factor = _get_two_factor(user)
    if not two_factor.is_enabled or not two_factor.is_configured:
        audit.log_event("account_delete_blocked_no_2fa", request=request, user=user)
        return _render_error("Two-factor authentication must be enabled first.", status=403)

    if _is_2fa_locked(user, request):
        audit.log_event("account_delete_locked", request=request, user=user)
        return _render_error(_RATE_LIMIT_ERROR, status=429)

    if not totp_service.verify_code(two_factor, request.POST.get("otp_code")):
        _record_2fa_failure(user, request)
        audit.log_event("account_delete_failed", request=request, user=user)
        return _render_error("Invalid 2FA code. Account deletion aborted.")

    _clear_2fa_failures(user, request)
    audit.log_event("account_deleted", request=request, user=user)
    logout(request)
    user.delete()
    return redirect("home")


# ---------------------------------------------------------------------------
# Chat API
# ---------------------------------------------------------------------------
def _json_error(message: str, status: int) -> JsonResponse:
    response = JsonResponse({"status": "error", "reply": message}, status=status)
    response["Cache-Control"] = "no-store"
    return response


@never_cache
@require_POST
def api_chat_view(request):
    if not request.user.is_authenticated:
        return _json_error("Authentication required.", 401)

    two_factor = _get_two_factor(request.user)
    if not two_factor.is_enabled or not two_factor.is_configured:
        return _json_error("Two-factor authentication required.", 403)

    if request.content_type != "application/json":
        return _json_error("Content-Type must be application/json.", 415)

    try:
        content_length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return _json_error("Invalid request.", 400)

    if content_length > settings.CHAT_MAX_BODY_BYTES:
        return _json_error("Request body is too large.", 413)

    if not ratelimit.allow(
        "chat:user",
        request.user.pk,
        limit=settings.CHAT_RATE_LIMIT_PER_MINUTE,
        window=60,
    ):
        audit.log_event("chat_rate_limited", request=request, user=request.user)
        return _json_error(_RATE_LIMIT_ERROR, 429)

    try:
        payload = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _json_error("Malformed JSON.", 400)

    if not isinstance(payload, dict):
        return _json_error("Malformed JSON.", 400)

    message = payload.get("message")
    if not isinstance(message, str) or not message.strip():
        return _json_error("Message cannot be empty.", 400)

    message = message.strip()
    if len(message) > settings.CHAT_MAX_MESSAGE_LENGTH:
        return _json_error(
            f"Message is too long (maximum {settings.CHAT_MAX_MESSAGE_LENGTH} characters).",
            400,
        )

    allowed, reason = ai_safety.screen_input(message)
    if not allowed:
        audit.log_event("chat_blocked", request=request, user=request.user, reason=reason)
        return _json_error(reason, 400)

    try:
        reply = ai.generate_reply(message)
    except ImproperlyConfigured:
        logger.error("Gemini client is not configured; chat request rejected")
        return _json_error("AI service is not configured.", 503)
    except Exception as exc:
        # Do not log the raw exception: SDK errors can include request URLs or
        # other sensitive metadata. The exception type is enough for triage.
        logger.error("Gemini request failed (%s)", type(exc).__name__)
        return _json_error("AI service is temporarily unavailable.", 502)

    reply = ai_safety.sanitize_output(reply)
    if not reply:
        logger.error("Gemini returned an empty response after sanitization")
        return _json_error("AI service returned an empty response.", 502)

    response = JsonResponse({"status": "success", "reply": reply})
    response["Cache-Control"] = "no-store"
    return response
