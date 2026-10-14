# ============================================================================
#  URL CONFIGURATION (api/urls.py)
# ============================================================================

from django.urls import path

urlpatterns = [
    path('generate-keys/', GenerateKeysView.as_view(), name='generate-keys'),
    path('analyze-strength/', AnalyzeStrengthView.as_view(), name='analyze-strength'),
    path('encrypt/', EncryptView.as_view(), name='encrypt'),
    path('decrypt/', DecryptView.as_view(), name='decrypt'),
    path('generate-and-analyze/', generate_and_analyze, name='generate-and-analyze'),
]
