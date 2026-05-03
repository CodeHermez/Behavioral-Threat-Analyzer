from django.urls import path
from . import views 

urlpatterns = [
    path("modal-single/", views.ModalSingle.as_view()),
    path("modal-csv/", views.ModalCSV.as_view()),
]