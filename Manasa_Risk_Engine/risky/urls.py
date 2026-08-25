from django.urls import path
from .views import RiskAnalysisView


urlpatterns = [
    path(
        "analyze/",
        RiskAnalysisView.as_view(),
        name="risk-analysis",
    ),
]