from django.urls import path
from . import views #views is where the logic stays and views would be the controller in the MVC not to be confused with the views archetecture but is in Django its calle dthe MTV

urlpatterns = [
    path("modal-single/", views.ModalSingle.as_view()),
    path("modal-csv/", views.ModalCSV.as_view()),
]