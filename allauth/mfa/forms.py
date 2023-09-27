import json

from django import forms
from django.utils.translation import gettext_lazy as _

from allauth.account.models import EmailAddress
from allauth.mfa import totp
from allauth.mfa.adapter import get_adapter
from allauth.mfa.models import Authenticator
from allauth.mfa.webauthn import (
    begin_authentication,
    begin_registration,
    complete_authentication,
    complete_registration,
    parse_authentication_credential,
    parse_registration_credential,
)


class AuthenticateForm(forms.Form):
    code = forms.CharField(label=_("Code"))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_code(self):
        code = self.cleaned_data["code"]
        for auth in Authenticator.objects.filter(user=self.user).exclude(
            type=Authenticator.Type.WEBAUTHN
        ):
            if auth.wrap().validate_code(code):
                self.authenticator = auth
                return code
        raise forms.ValidationError(get_adapter().error_messages["incorrect_code"])

    def save(self):
        self.authenticator.record_usage()


class AuthenticateWebAuthnForm(forms.Form):
    credential = forms.CharField(required=True, widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.authentication_data = begin_authentication(self.user)
        super().__init__(*args, **kwargs)

    def clean_credential(self):
        credential = self.cleaned_data["credential"]
        user, credential = parse_authentication_credential(json.loads(credential))
        # FIXME: Raise form error
        assert self.user.pk == user.pk
        return complete_authentication(user, credential)

    def save(self):
        authenticator = self.cleaned_data["credential"]
        authenticator.record_usage()


class ActivateTOTPForm(forms.Form):
    code = forms.CharField(label=_("Authenticator code"))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.email_verified = not EmailAddress.objects.filter(
            user=self.user, verified=False
        ).exists()
        super().__init__(*args, **kwargs)
        self.secret = totp.get_totp_secret(regenerate=not self.is_bound)

    def clean_code(self):
        try:
            code = self.cleaned_data["code"]
            if not self.email_verified:
                raise forms.ValidationError(
                    get_adapter().error_messages["unverified_email"]
                )
            if not totp.validate_totp_code(self.secret, code):
                raise forms.ValidationError(
                    get_adapter().error_messages["incorrect_code"]
                )
            return code
        except forms.ValidationError as e:
            self.secret = totp.get_totp_secret(regenerate=True)
            raise e


class AddWebAuthnForm(forms.Form):
    name = forms.CharField(required=False)
    passwordless = forms.BooleanField(
        label=_("Passwordless"),
        required=False,
        help_text=_(
            "Enabling passwordless operation allows you to sign in using just this key/device, but imposes additional requirements such as biometrics or PIN protection."
        ),
    )
    credential = forms.CharField(required=True, widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.registration_data = begin_registration(self.user)
        super().__init__(*args, **kwargs)

    def clean_credential(self):
        credential = self.cleaned_data["credential"]
        return parse_registration_credential(json.loads(credential))

    def clean(self):
        cleaned_data = super().clean()
        credential = cleaned_data.get("credential")
        passwordless = cleaned_data.get("passwordless")
        if credential:
            if (
                passwordless
                and not credential["attestation_object"].auth_data.is_user_verified()
            ):
                self.add_error(
                    None, _("This key does not support passwordless operation.")
                )
            else:
                cleaned_data["authenticator_data"] = complete_registration(credential)
        return cleaned_data
