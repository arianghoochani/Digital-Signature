
from django.urls import path
from . import views
urlpatterns = [
    path('sign/',views.sign,name="sign"),
]
