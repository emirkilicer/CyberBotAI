"""Project middleware: 2FA gating, CSP, admin protection."""

from __future__ import annotations

import ipaddress
import secrets

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect

from .models import UserTwoFactor
from .services import audit, ratelimit

SESSION_2FA_KEY = "auth_2fa_verified"


class SecurityHeadersMiddleware:
    """Per-request nonce based CSP plus Permissions-Policy.

    The Django admin still uses inline event handlers/scripts, so it gets a
    relaxed script-src. Application pages use a nonce for the single inline
    script in index.html.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce
        response = self.get_response(request)

        if request.path.startswith("/admin/"):
            script_src = "'self' 'unsafe-inline'"
        else:
            script_src = f"'self' 'nonce-{nonce}' https://cdn.jsdelivr.net"

        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src {script_src}; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "media-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        return response


class AdminIPAllowlistMiddleware:
    """Optional network allowlist for the Django admin.

    Set ADMIN_IP_ALLOWLIST=10.0.0.0/8,192.168.1.10 in production. IPv4/IPv6
    addresses and CIDR networks are accepted. An empty list keeps local
    development usable.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def _allowed(ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in settings.ADMIN_IP_ALLOWLIST:
            try:
                if "/" in entry:
                    if address in ipaddress.ip_network(entry, strict=False):
                        return True
                elif address == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def __call__(self, request):
        if request.path.startswith("/admin/") and settings.ADMIN_IP_ALLOWLIST:
            ip = ratelimit.client_ip(request)
            if not self._allowed(ip):
                audit.log_event("admin_ip_blocked", request=request)
                return HttpResponse("Forbidden.", status=403, content_type="text/plain")
        return self.get_response(request)


class Require2FAForAuthenticatedMiddleware:
    """Only allow sessions that completed the TOTP step.

    Django's admin login form authenticates with a password only. Without this
    gate, a password-only admin session (or any stale session created before
    the 2FA flow existed) could reach profile/chat/admin endpoints while the
    account merely *has* 2FA enabled. The session marker is set only after a
    successful TOTP verification.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and not request.session.get(SESSION_2FA_KEY):
            if request.path.startswith("/logout/"):
                return self.get_response(request)

            logout(request)
            if request.path.startswith("/api/"):
                response = JsonResponse(
                    {"status": "error", "reply": "Two-factor authentication required."},
                    status=401,
                )
                response["Cache-Control"] = "no-store"
                return response
            return redirect("login")

        # Defense in depth: admin access also requires an enabled factor.
        if request.path.startswith("/admin/") and request.user.is_authenticated:
            factor = (
                UserTwoFactor.objects.filter(user_id=request.user.pk, is_enabled=True)
                .only("otp_secret")
                .first()
            )
            if factor is None or not factor.otp_secret:
                logout(request)
                return redirect("login")

        return self.get_response(request)


class AdminLoginThrottleMiddleware:
    """Rate limit Django's built-in admin password form.

    The application login has its own limiter; /admin/login/ would otherwise
    allow unlimited password guesses.
    """

    LOGIN_PATH = "/admin/login/"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path != self.LOGIN_PATH or request.method != "POST":
            return self.get_response(request)

        ip = ratelimit.client_ip(request)
        username = (request.POST.get("username") or "").strip().lower()

        if ratelimit.is_locked("admin_login:ip", ip) or ratelimit.is_locked(
            "admin_login:user", username
        ):
            audit.log_event("admin_login_locked", request=request, username=username)
            response = HttpResponse(
                "Too many login attempts. Try again later.",
                status=429,
                content_type="text/plain",
            )
            response["Retry-After"] = str(settings.ADMIN_LOGIN_WINDOW_SECONDS)
            return response

        response = self.get_response(request)
        success = response.status_code in (301, 302, 303) and request.user.is_authenticated

        if success:
            ratelimit.clear_failures("admin_login:ip", ip)
            ratelimit.clear_failures("admin_login:user", username)
            audit.log_event("admin_login_success", request=request, user=request.user)
        else:
            limit = settings.ADMIN_LOGIN_ATTEMPT_LIMIT
            window = settings.ADMIN_LOGIN_WINDOW_SECONDS
            ratelimit.record_failure(
                "admin_login:ip", ip, limit=limit * 3, window=window, lockout=window
            )
            ratelimit.record_failure(
                "admin_login:user", username, limit=limit, window=window, lockout=window
            )
            audit.log_event("admin_login_failed", request=request, username=username)

        return response
