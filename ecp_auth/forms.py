from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm


class ECPRegisterForm(UserCreationForm):
    """Registration form that extends UserCreationForm with an ECP key password field."""

    key_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Пароль для ключа",
        help_text="Захищає приватний ключ. Збережіть його — без нього вхід неможливий.",
    )

    class Meta(UserCreationForm.Meta):
        """Use the same model as UserCreationForm with a fixed set of fields."""

        model = get_user_model()
        fields = ("username", "password1", "password2")


class ECPLoginForm(forms.Form):
    """Login form that collects credentials alongside an ECP nonce and signature."""

    username = forms.CharField(label="Логін")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")
    nonce_id = forms.IntegerField(widget=forms.HiddenInput, required=False)
    signature = forms.CharField(widget=forms.HiddenInput, required=False)

    def clean_signature(self) -> bytes:
        """Decode the hex-encoded signature to raw bytes."""
        hex_sig = self.cleaned_data.get("signature", "")
        if not hex_sig:
            raise forms.ValidationError("Підпис відсутній — JS не завершив підписання")
        try:
            return bytes.fromhex(hex_sig)
        except ValueError:
            raise forms.ValidationError("Підпис у невалідному форматі")  # noqa: RUF001

    def clean_nonce_id(self) -> int:
        """Ensure nonce_id is present."""
        val = self.cleaned_data.get("nonce_id")
        if val is None:
            raise forms.ValidationError("Nonce відсутній — оновіть сторінку")
        return val
