from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

import re


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
        )
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
        ),
        label="Confirm Password",
    )

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name"]
        widgets = {
            "username": forms.TextInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
            "email": forms.EmailInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
            "first_name": forms.TextInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
            "last_name": forms.TextInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
        }

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if username and User.objects.filter(username__iexact=username).exists():
            # Keep the message generic; a username-based signup cannot fully
            # hide availability, but it should not confirm account details.
            raise ValidationError("This username is not available.")
        return username

    def clean_password(self):
        password = self.cleaned_data.get("password")

        if password:
            # Reuse Django's configured validators (minimum length, common
            # passwords, numeric-only, similarity to user attributes).
            candidate = User(
                username=self.data.get("username", ""),
                email=self.data.get("email", ""),
                first_name=self.data.get("first_name", ""),
                last_name=self.data.get("last_name", ""),
            )
            try:
                validate_password(password, user=candidate)
            except ValidationError as exc:
                raise ValidationError(exc.messages) from exc

            if len(password) < 8:
                raise ValidationError("Password must be at least 8 characters long.")
            if not re.search(r"[A-Z]", password):
                raise ValidationError("Password must contain at least one uppercase letter.")
            if not re.search(r"[a-z]", password):
                raise ValidationError("Password must contain at least one lowercase letter.")
            if not re.search(r"[0-9]", password):
                raise ValidationError("Password must contain at least one number.")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                raise ValidationError(
                    "Password must contain at least one special character (!@#$ vb.)."
                )

        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError("Şifreler eşleşmiyor!")
        return cleaned_data


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
            "last_name": forms.TextInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
            "email": forms.EmailInput(
                attrs={"class": "form-control bg-transparent text-white border-secondary rounded-0"}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["first_name"].required = True
        self.fields["last_name"].required = True
        self.fields["email"].required = True
