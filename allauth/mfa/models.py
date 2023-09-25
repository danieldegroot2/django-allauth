from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class AuthenticatorManager(models.Manager):
    def delete_dangling_recovery_codes(self, user):
        qs = Authenticator.objects.filter(user=user)
        if not qs.exclude(type=Authenticator.Type.RECOVERY_CODES).exists():
            qs.delete()


class Authenticator(models.Model):
    class Type(models.TextChoices):
        RECOVERY_CODES = "recovery_codes", _("Recovery codes")
        TOTP = "totp", _("TOTP Authenticator")
        WEBAUTHN = "webauthn", _("WebAuthn")

    objects = AuthenticatorManager()

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    type = models.CharField(max_length=20, choices=Type.choices)
    data = models.JSONField()
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True)

    class Meta:
        unique_together = (("user", "type"),)

    def wrap(self):
        from allauth.mfa.recovery_codes import RecoveryCodes
        from allauth.mfa.totp import TOTP
        from allauth.mfa.webauthn import WebAuthn

        return {
            self.Type.TOTP: TOTP,
            self.Type.RECOVERY_CODES: RecoveryCodes,
            self.Type.WEBAUTHN: WebAuthn,
        }[self.type](self)

    def record_usage(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])
