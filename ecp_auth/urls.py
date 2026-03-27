from django.urls import path

from .views import CertificateUploadView, ChallengeView, KeyDisplayView

urlpatterns = [
    path("challenge/", ChallengeView.as_view(), name="challenge"),
    path("keys/", KeyDisplayView.as_view(), name="keys"),
    path("certificate/", CertificateUploadView.as_view(), name="certificate-upload"),
]
