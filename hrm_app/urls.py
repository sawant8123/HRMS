from django.urls import path
from .views import custom_login_view
from . import views

urlpatterns = [
    path('departments/', views.department_list, name='department_list'),
    path('departments/create/', views.department_create, name='department_create'),
    path('departments/update/<int:pk>/', views.department_update, name='department_update'),
    path('departments/delete/<int:pk>/', views.department_delete, name='department_delete'),
    path('login/', custom_login_view, name='login'),
]
