from django import forms
from django.contrib.auth.forms import UserCreationForm


class ECPRegisterForm(UserCreationForm):
    key_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Пароль для ключа",
        help_text="Захищає приватний ключ. Збережіть його — без нього вхід неможливий.",
    )

    class Meta(UserCreationForm.Meta):
        fields = ("username", "password1", "password2")


class ECPLoginForm(forms.Form):
    username = forms.CharField(label="Логін")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")
    nonce_id = forms.IntegerField(widget=forms.HiddenInput, required=False)
    signature = forms.CharField(widget=forms.HiddenInput, required=False)

    def clean_signature(self) -> bytes:
        hex_sig = self.cleaned_data.get("signature", "")
        if not hex_sig:
            raise forms.ValidationError("Підпис відсутній — JS не завершив підписання")
        try:
            return bytes.fromhex(hex_sig)
        except ValueError:
            raise forms.ValidationError("Підпис у невалідному форматі")

    def clean_nonce_id(self) -> int:
        val = self.cleaned_data.get("nonce_id")
        if val is None:
            raise forms.ValidationError("Nonce відсутній — оновіть сторінку")
        return val
