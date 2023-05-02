from django.utils.translation import gettext_lazy as _
from two_factor.forms import AuthenticationTokenForm, BackupTokenForm, TOTPDeviceForm


class TwoFactorSetupTokenForm(TOTPDeviceForm):
    """
    This is an adaptation of the built-in two factor form.
    The user can create a token with a QR code or secret key.
    The two factor is setup with the token and is validated and created with this form.
    """

    def __init__(self, key, user, **kwargs):
        super().__init__(key, user, **kwargs)
        self.fields["token"].widget.attrs.update({"autocomplete": "off"})
        self.fields["token"].help_text = _(
            "Insert the token generated by the authenticator app to setup the two factor authentication."
        )


class TwoFactorVerifyTokenForm(AuthenticationTokenForm):
    """
    This is an adaptation of the token verification form,
    so after user has logged in. (This is not the token setup form)
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fields["otp_token"].widget.attrs.update({"autocomplete": "off"})
        self.fields["otp_token"].help_text = _("Insert the token generated by your token authenticator app.")


class TwoFactorBackupTokenForm(BackupTokenForm):
    """
    This is an adaptation of the BackupTokenForm.
    The user can create a set of backup tokens at token setup and
    use this form to enter a valid token.
    """

    def __init__(self, user, initial_device, **kwargs):
        super().__init__(user, initial_device, **kwargs)
        self.fields["otp_token"].widget.attrs.update({"autocomplete": "off"})
        self.fields["otp_token"].label = _("Backup token")
