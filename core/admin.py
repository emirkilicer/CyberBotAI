from django.contrib import admin

from .models import UserTwoFactor


@admin.register(UserTwoFactor)
class UserTwoFactorAdmin(admin.ModelAdmin):
    list_display = ("user", "is_enabled", "updated_at")
    list_filter = ("is_enabled",)
    list_select_related = ("user",)
    search_fields = ("user__username", "user__email")
    readonly_fields = ("last_used_step", "updated_at")
    # The encrypted secret should not be browseable in the admin UI.
    exclude = ("otp_secret",)
