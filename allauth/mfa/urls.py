from django.urls import include, path

from allauth.mfa import views


urlpatterns = [
    path("", views.index, name="mfa_index"),
    path("authenticate/", views.authenticate, name="mfa_authenticate"),
    path(
        "totp/",
        include(
            [
                path("activate/", views.activate_totp, name="mfa_activate_totp"),
                path("deactivate/", views.deactivate_totp, name="mfa_deactivate_totp"),
            ]
        ),
    ),
    path(
        "webauthn/",
        include(
            [
                path("", views.list_webauthn, name="mfa_list_webauthn"),
                path("add/", views.add_webauthn, name="mfa_add_webauthn"),
                path(
                    "<int:pk>/remove/",
                    views.remove_webauthn,
                    name="mfa_remove_webauthn",
                ),
            ]
        ),
    ),
    path(
        "recovery-codes/",
        include(
            [
                path("", views.view_recovery_codes, name="mfa_view_recovery_codes"),
                path(
                    "generate/",
                    views.generate_recovery_codes,
                    name="mfa_generate_recovery_codes",
                ),
                path(
                    "download/",
                    views.download_recovery_codes,
                    name="mfa_download_recovery_codes",
                ),
            ]
        ),
    ),
]
