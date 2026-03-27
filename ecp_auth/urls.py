from django.urls import path

from .views import ChallengeView, KeyDisplayView

urlpatterns = [
    path("challenge/", ChallengeView.as_view(), name="challenge"),
    path("keys/", KeyDisplayView.as_view(), name="keys"),
]
