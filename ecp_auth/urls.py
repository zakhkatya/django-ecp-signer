from django.urls import path
from .views import ChallengeView, CertificateDownloadView

pythonurlpatterns = [
    path('challenge/', ChallengeView.as_view(), name='challenge'),
    path('certificate/download/', CertificateDownloadView.as_view(), name='download'),
]