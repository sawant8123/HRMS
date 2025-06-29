from django.urls import path
from .views import custom_login_view
from . import views

urlpatterns = [
    path('', views.admin_login_view, name='root_login'),  # root always admin login
    path('login/', views.admin_login_view, name='login'), # /login/ always admin login
    path('admin-login/', views.admin_login_view, name='admin_login'),
    path('employee-login/', views.employee_login_view, name='employee_login'),
    path('employee-signup/', views.employee_signup_view, name='employee_signup'),
    path('employee-verify-email/<int:user_id>/', views.employee_verify_email, name='employee_verify_email'),
    path('resend-otp/<int:user_id>/', views.resend_otp, name='resend_otp'),
    path('employee-dashboard/', views.employee_dashboard, name='employee_dashboard'),
    path('logout/', views.logout_view, name='logout'),
    
    # Department URLs
    path('departments/', views.department_list, name='department_list'),
    path('departments/create/', views.department_create, name='department_create'),
    path('departments/<int:pk>/update/', views.department_update, name='department_update'),
    path('departments/<int:pk>/delete/', views.department_delete, name='department_delete'),
    path('departments/<int:pk>/reactivate/', views.department_reactivate, name='department_reactivate'),
    path('roles/', views.role_list, name='role_list'),
    path('roles/create/', views.role_create, name='role_create'),
    path('roles/<int:pk>/edit/', views.role_update, name='role_update'),
    path('roles/<int:pk>/delete/', views.role_delete, name='role_delete'),
    path('roles/<int:pk>/reactivate/', views.role_reactivate, name='role_reactivate'),
    path('employees/', views.employee_list, name='employee_list'),
    path('employees/create/', views.employee_create, name='employee_create'),
    path('employees/<int:pk>/edit/', views.employee_update, name='employee_update'),
    path('employees/<int:pk>/delete/', views.employee_delete, name='employee_delete'),
    path('password-reset/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/otp/', views.password_reset_otp, name='password_reset_otp'),
    path('password-reset/new/', views.password_reset_new, name='password_reset_new'),
    # Task Management URLs
    path('tasks/create/', views.task_create, name='task_create'),
    path('tasks/', views.task_dashboard, name='task_dashboard'),
    path('tasks/<int:pk>/edit/', views.task_update, name='task_update'),
    path('tasks/<int:pk>/delete/', views.task_delete, name='task_delete'),
    path('tasks/<int:pk>/', views.task_detail, name='task_detail'),
    # Performance Review URLs
    path('reviews/', views.review_dashboard, name='review_dashboard'),
    path('reviews/create/', views.review_create, name='review_create'),
    path('reviews/<int:pk>/edit/', views.review_update, name='review_update'),
    path('reviews/<int:pk>/delete/', views.review_delete, name='review_delete'),
    path('reviews/<int:pk>/', views.review_detail, name='review_detail'),
    # Leave Management URLs
    path('employee/leaves/', views.employee_leave_dashboard, name='employee_leave_dashboard'),
    path('employee/leaves/apply/', views.apply_leave, name='apply_leave'),
    path('employee/leaves/edit/<int:leave_id>/', views.edit_leave, name='edit_leave'),
    path('leaves/admin/', views.admin_leave_dashboard, name='admin_leave_dashboard'),
    path('leaves/admin/approve/<int:leave_id>/', views.approve_leave, name='approve_leave'),
    path('leaves/admin/reject/<int:leave_id>/', views.reject_leave, name='reject_leave'),
]
