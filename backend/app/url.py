from django.urls import path
from . import views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
#api documentation

# routes for the api and documentation
urlpatterns = [
    path("modal-sample/", views.ModalSampleView.as_view()),
    path("modal-csv/", views.ModalCsvView.as_view()),
    path("modal-csv/results/", views.ModalCsvResultsView.as_view()),
    path("modal-csv/analyze/", views.ModalCsvAnalyzeView.as_view()),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema')),
]