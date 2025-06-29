from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django import forms
from .models import Department, Role, User, Task, TaskAssignment, PerformanceReview, Leave, LeaveQuota
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse
from django.db.models import Q
from django.core.mail import send_mail
import random, string, datetime
from django.utils import timezone
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse
from .forms import PasswordResetRequestForm, OTPForm, SetNewPasswordForm, TaskForm, TaskAssignmentForm, PerformanceReviewForm, LeaveForm, LeaveQuotaForm
from django.core.paginator import Paginator
from django.db.models import Count, Avg
import logging

# Create your views here.

# Inline form inside views.py
class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ['name', 'description']

class InlineRoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['role_name', 'description', 'status']
        widgets = {
            'role_name': forms.TextInput(attrs={'class': 'form-control rounded-start px-3 py-2'}),
            'description': forms.Textarea(attrs={'class': 'form-control rounded-start px-3 py-2', 'rows': 3}),
            'status': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

# Inline User form
class InlineUserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), required=False)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'mobile', 'dept', 'role', 'reporting_manager', 'date_of_joining']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'mobile': forms.TextInput(attrs={'class': 'form-control'}),
            'dept': forms.Select(attrs={'class': 'form-select'}),
            'role': forms.Select(attrs={'class': 'form-select'}),
            'reporting_manager': forms.Select(attrs={'class': 'form-select'}),
            'date_of_joining': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        }
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['role'].empty_label = 'Select Role'
        self.fields['dept'].empty_label = 'Select Department'
        self.fields['reporting_manager'].empty_label = 'Select Reporting Manager'
        # Make password required only for new users
        if self.instance and self.instance.pk:
            self.fields['password'].help_text = 'Leave blank to keep current password'
        else:
            self.fields['password'].required = True
            self.fields['password'].help_text = 'Required for new employees'

# Employee Signup Form
class EmployeeSignupForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'}))
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'mobile']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'}),
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}),
            'mobile': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Mobile Number'}),
        }

    def clean_confirm_password(self):
        password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords don't match")
        return confirm_password

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists")
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists")
        return username

# Employee Login Form
class EmployeeLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))

# Admin Login Form
class AdminLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Admin Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Admin Password'}))

# Only allow admin
admin_required = user_passes_test(lambda u: u.is_superuser)

# Only allow admin or HR (role name 'Admin' or 'HR')
def admin_or_hr_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated:
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            if hasattr(request.user, 'role') and request.user.role:
                if request.user.role.role_name in ['Admin', 'HR']:
                    return view_func(request, *args, **kwargs)
        messages.error(request, 'Access denied. Admin or HR privileges required.')
        return redirect('login')
    return _wrapped_view

# Admin Login View
def admin_login_view(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('department_list')
    
    if request.method == 'POST':
        form = AdminLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            
            if user is not None and user.is_superuser:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!')
                return redirect('department_list')
            else:
                messages.error(request, 'Invalid admin credentials.')
    else:
        form = AdminLoginForm()
    
    return render(request, 'hrm_app/admin_login.html', {'form': form})

# Employee Login View
def employee_login_view(request):
    logger = logging.getLogger(__name__)
    if request.user.is_authenticated and request.user.is_employee:
        logger.debug('User already authenticated and is employee, redirecting to dashboard.')
        return redirect('employee_dashboard')
    
    if request.method == 'POST':
        form = EmployeeLoginForm(request.POST)
        logger.debug(f'POST data: {request.POST}')
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            logger.debug(f'Form valid. Username: {username}')
            user = authenticate(request, username=username, password=password)
            logger.debug(f'Authenticate result: {user}')
            if user is not None:
                logger.debug(f'User is_employee: {getattr(user, "is_employee", None)}, status: {getattr(user, "status", None)}, email_verified: {getattr(user, "email_verified", None)}')
            if user is not None and user.is_employee and user.status:
                if user.email_verified:
                    login(request, user)
                    messages.success(request, f'Welcome back, {user.first_name}!')
                    logger.debug('Login successful, redirecting to dashboard.')
                    return redirect('employee_dashboard')
                else:
                    messages.error(request, 'Please verify your email first.')
                    logger.debug('Email not verified.')
            else:
                messages.error(request, 'Invalid credentials or account inactive.')
                logger.debug('Invalid credentials or account inactive.')
        else:
            logger.debug(f'Form invalid: {form.errors}')
    else:
        form = EmployeeLoginForm()
    
    return render(request, 'hrm_app/employee_login.html', {'form': form})

# Employee Signup View
def employee_signup_view(request):
    if request.method == 'POST':
        form = EmployeeSignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_employee = True
            user.is_staff = False
            user.is_superuser = False
            user.set_password(form.cleaned_data['password'])
            
            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.save()
            
            # Send OTP email
            try:
                send_mail(
                    'Email Verification - HRMS',
                    f'Your verification OTP is: {otp}\n\nThis OTP will expire in 10 minutes.',
                    'noreply@hrms.com',
                    [user.email],
                    fail_silently=False,
                )
                messages.success(request, 'Account created! Please check your email for verification OTP.')
                return redirect('employee_verify_email', user_id=user.id)
            except Exception as e:
                user.delete()
                messages.error(request, 'Failed to send verification email. Please try again.')
    else:
        form = EmployeeSignupForm()
    
    return render(request, 'hrm_app/employee_signup.html', {'form': form})

# Email Verification View
def employee_verify_email(request, user_id):
    user = get_object_or_404(User, id=user_id, is_employee=True)
    
    if request.method == 'POST':
        otp = request.POST.get('otp')
        if otp == user.otp:
            # Check if OTP is not expired (10 minutes)
            if user.otp_created_at and (timezone.now() - user.otp_created_at).seconds < 600:
                user.email_verified = True
                user.otp = None
                user.otp_created_at = None
                user.save()
                messages.success(request, 'Email verified successfully! You can now login.')
                return redirect('employee_login')
            else:
                messages.error(request, 'OTP has expired. Please request a new one.')
        else:
            messages.error(request, 'Invalid OTP.')
    
    return render(request, 'hrm_app/employee_verify_email.html', {'user': user})

# Resend OTP View
def resend_otp(request, user_id):
    user = get_object_or_404(User, id=user_id, is_employee=True)
    
    # Generate new OTP
    otp = ''.join(random.choices(string.digits, k=6))
    user.otp = otp
    user.otp_created_at = timezone.now()
    user.save()
    
    # Send new OTP email
    try:
        send_mail(
            'Email Verification - HRMS',
            f'Your new verification OTP is: {otp}\n\nThis OTP will expire in 10 minutes.',
            'noreply@hrms.com',
            [user.email],
            fail_silently=False,
        )
        messages.success(request, 'New OTP sent to your email!')
    except Exception as e:
        messages.error(request, 'Failed to send OTP. Please try again.')
    
    return redirect('employee_verify_email', user_id=user.id)

# Employee Dashboard View
@login_required
def employee_dashboard(request):
    if not request.user.is_employee:
        messages.error(request, 'Access denied. Employee privileges required.')
        return redirect('admin_login')
    user = request.user
    # Get tasks assigned to this employee
    tasks = TaskAssignment.objects.filter(employee=user).select_related('task')
    # Get performance reviews for this employee
    reviews = PerformanceReview.objects.filter(employee=user)
    # Get leave quotas and leaves for this employee
    quotas = LeaveQuota.objects.filter(employee=user)
    quota_dict = {q.leave_type: q for q in quotas}
    leaves = Leave.objects.filter(employee=user).order_by('-start_date')
    return render(request, 'hrm_app/employee_dashboard.html', {
        'user': user,
        'tasks': tasks,
        'reviews': reviews,
        'quota_dict': quota_dict,
        'leaves': leaves,
    })

# Logout View
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('admin_login')

@login_required
def department_list(request):
    search_query = request.GET.get('search', '').strip()
    filter_option = request.GET.get('active', '1')  # '1' = active, '0' = all, '2' = inactive
    departments = Department.objects.all()
    if search_query:
        departments = departments.filter(
            name__icontains=search_query
        )
    if filter_option == '1':
        departments = departments.exclude(name__icontains='[INACTIVE]')
    elif filter_option == '2':
        departments = departments.filter(name__icontains='[INACTIVE]')
    # else '0': show all
    return render(request, 'hrm_app/department_list.html', {
        'departments': departments,
        'search_query': search_query,
        'filter_option': filter_option,
    })

@login_required
def department_create(request):
    if request.method == 'POST':
        form = DepartmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Department added successfully.")
            return redirect('department_list')
    else:
        form = DepartmentForm()
    return render(request, 'hrm_app/department_form.html', {'form': form})

@login_required
def department_update(request, pk):
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        form = DepartmentForm(request.POST, instance=department)
        if form.is_valid():
            form.save()
            messages.success(request, "Department updated successfully.")
            return redirect('department_list')
    else:
        form = DepartmentForm(instance=department)
    return render(request, 'hrm_app/department_form.html', {'form': form})

@login_required
def department_delete(request, pk):
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        # Instead of deleting, mark as inactive
        if '[INACTIVE]' not in department.name:
            department.name = department.name + ' [INACTIVE]'
            department.save()
        messages.warning(request, "Department marked as inactive.")
        return redirect('department_list')
    return render(request, 'hrm_app/department_confirm_delete.html', {'department': department})

def custom_login_view(request):
    # Redirect to admin login page
    return redirect('admin_login')

@admin_required
def role_list(request):
    search_query = request.GET.get('search', '').strip()
    filter_option = request.GET.get('active', '1')  # '1' = active, '0' = all, '2' = inactive
    roles = Role.objects.all()
    if search_query:
        roles = roles.filter(role_name__icontains=search_query)
    if filter_option == '1':
        roles = roles.filter(status=True)
    elif filter_option == '2':
        roles = roles.filter(status=False)
    # else '0': show all
    return render(request, 'hrm_app/role_list.html', {
        'roles': roles,
        'search_query': search_query,
        'filter_option': filter_option,
    })

@admin_required
def role_create(request):
    if request.method == 'POST':
        form = InlineRoleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Role created successfully.')
            return redirect('role_list')
    else:
        form = InlineRoleForm()
    return render(request, 'hrm_app/role_form.html', {'form': form, 'title': 'Create Role'})

@admin_required
def role_update(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        form = InlineRoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            messages.success(request, 'Role updated successfully.')
            return redirect('role_list')
    else:
        form = InlineRoleForm(instance=role)
    return render(request, 'hrm_app/role_form.html', {'form': form, 'title': 'Edit Role'})

@admin_required
def role_delete(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        role.status = False  # Soft delete
        role.save()
        messages.warning(request, 'Role has been made inactive.')
        return redirect('role_list')
    return render(request, 'hrm_app/role_confirm_delete.html', {'role': role})

@admin_required
def department_reactivate(request, pk):
    department = get_object_or_404(Department, pk=pk)
    if '[INACTIVE]' in department.name:
        department.name = department.name.replace(' [INACTIVE]', '')
    department.save()
    messages.success(request, 'Department reactivated successfully.')
    # Redirect to active filter
    return redirect('/departments/?active=1')

@admin_required
def role_reactivate(request, pk):
    role = get_object_or_404(Role, pk=pk)
    role.status = True
    role.save()
    messages.success(request, 'Role reactivated successfully.')
    # Redirect to active filter
    return redirect('/roles/?active=1')

@admin_or_hr_required
def employee_list(request):
    search_query = request.GET.get('search', '').strip()
    filter_option = request.GET.get('active', '1')  # '1' = active, '0' = all, '2' = inactive
    employees = User.objects.filter(is_employee=True)
    
    if search_query:
        employees = employees.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(username__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    if filter_option == '1':
        employees = employees.filter(status=True)
    elif filter_option == '2':
        employees = employees.filter(status=False)
    # else '0': show all
    
    return render(request, 'hrm_app/employee_list.html', {
        'employees': employees,
        'search_query': search_query,
        'filter_option': filter_option,
    })

@admin_or_hr_required
def employee_create(request):
    if request.method == 'POST':
        form = InlineUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_employee = True
            user.is_staff = False
            user.is_superuser = False
            user.set_password(form.cleaned_data['password'])
            user.save()
            messages.success(request, 'Employee added successfully.')
            return redirect('employee_list')
    else:
        form = InlineUserForm()
    return render(request, 'hrm_app/employee_form.html', {'form': form, 'title': 'Add Employee'})

@admin_or_hr_required
def employee_update(request, pk):
    employee = get_object_or_404(User, pk=pk, is_employee=True)
    if request.method == 'POST':
        form = InlineUserForm(request.POST, instance=employee)
        if form.is_valid():
            user = form.save(commit=False)
            # Only update password if a new one is provided
            if form.cleaned_data['password']:
                user.set_password(form.cleaned_data['password'])
            user.save()
            messages.success(request, 'Employee updated successfully.')
            return redirect('employee_list')
    else:
        form = InlineUserForm(instance=employee)
    return render(request, 'hrm_app/employee_form.html', {'form': form, 'title': 'Edit Employee'})

@admin_or_hr_required
def employee_delete(request, pk):
    employee = get_object_or_404(User, pk=pk, is_employee=True)
    if request.method == 'POST':
        employee.status = False  # Soft delete
        employee.save()
        messages.warning(request, 'Employee marked as inactive.')
        return redirect('employee_list')
    return render(request, 'hrm_app/employee_confirm_delete.html', {'employee': employee})

# Helper for OTP
OTP_EXPIRY_MINUTES = 10
OTP_SESSION_KEY = 'reset_otp'
OTP_EMAIL_SESSION_KEY = 'reset_email'
OTP_TIME_SESSION_KEY = 'reset_otp_time'

# Password Reset Request View

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email, is_employee=True)
                if not user.email_verified:
                    messages.error(request, 'Please verify your email first before resetting password.')
                    return render(request, 'hrm_app/password_reset_request.html', {'form': form})
            except User.DoesNotExist:
                messages.error(request, 'No employee found with this email.')
                return render(request, 'hrm_app/password_reset_request.html', {'form': form})
            
            otp = ''.join(random.choices(string.digits, k=6))
            request.session[OTP_SESSION_KEY] = otp
            request.session[OTP_EMAIL_SESSION_KEY] = email
            request.session[OTP_TIME_SESSION_KEY] = timezone.now().isoformat()
            
            try:
                send_mail(
                    'Your HRMS Password Reset OTP',
                    f'Your OTP for password reset is: {otp}\n\nThis OTP will expire in 10 minutes.',
                    'noreply@hrms.com',
                    [email],
                    fail_silently=False,
                )
                return redirect('password_reset_otp')
            except Exception as e:
                messages.error(request, 'Failed to send OTP. Please try again.')
                return render(request, 'hrm_app/password_reset_request.html', {'form': form})
    else:
        form = PasswordResetRequestForm()
    return render(request, 'hrm_app/password_reset_request.html', {'form': form})

# OTP Verification View

def password_reset_otp(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        otp = request.session.get(OTP_SESSION_KEY)
        otp_time = request.session.get(OTP_TIME_SESSION_KEY)
        email = request.session.get(OTP_EMAIL_SESSION_KEY)
        
        if not otp or not otp_time or not email:
            messages.error(request, 'OTP session expired. Please try again.')
            return redirect('password_reset_request')
        
        if form.is_valid():
            otp_input = form.cleaned_data['otp']
            # Check if OTP is expired (10 minutes)
            otp_created = datetime.datetime.fromisoformat(otp_time)
            if (timezone.now() - otp_created).total_seconds() > 600:
                messages.error(request, 'OTP has expired. Please request a new one.')
                return render(request, 'hrm_app/password_reset_request.html', {'form': PasswordResetRequestForm(initial={'email': email})})
            if otp_input == otp:
                return redirect('password_reset_new')
            else:
                messages.error(request, 'Invalid OTP.')
                return render(request, 'hrm_app/password_reset_otp.html', {'form': form})
    else:
        form = OTPForm()
    return render(request, 'hrm_app/password_reset_otp.html', {'form': form})

# Set New Password View

def password_reset_new(request):
    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        email = request.session.get(OTP_EMAIL_SESSION_KEY)
        if not email:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('password_reset_request')
        if form.is_valid():
            password1 = form.cleaned_data['new_password']
            user = User.objects.get(email=email, is_employee=True)
            user.set_password(password1)
            user.save()
            # Optionally clear session
            request.session.pop(OTP_SESSION_KEY, None)
            request.session.pop(OTP_EMAIL_SESSION_KEY, None)
            request.session.pop(OTP_TIME_SESSION_KEY, None)
            messages.success(request, 'Password reset successful. Please login.')
            return redirect('employee_login')
        else:
            return render(request, 'hrm_app/password_reset_new.html', {'form': form})
    else:
        form = SetNewPasswordForm()
    return render(request, 'hrm_app/password_reset_new.html', {'form': form})

@login_required
def task_create(request):
    if not (request.user.is_superuser or (hasattr(request.user, 'role') and request.user.role and request.user.role.role_name in ['Admin', 'HR', 'Manager', 'Team Leader'])):
        messages.error(request, 'Access denied. Only Admin, HR, Manager, or Team Leader can create tasks.')
        return redirect('employee_dashboard')
    if request.method == 'POST':
        form = TaskForm(request.POST)
        assignment_form = TaskAssignmentForm(request.POST)
        if form.is_valid() and assignment_form.is_valid():
            task = form.save()
            assignment = assignment_form.save(commit=False)
            assignment.task = task
            assignment.assigned_by = request.user
            assignment.save()
            messages.success(request, 'Task created and assigned successfully.')
            return redirect('task_dashboard')
    else:
        form = TaskForm()
        assignment_form = TaskAssignmentForm()
    return render(request, 'hrm_app/task_create.html', {'form': form, 'assignment_form': assignment_form})

@login_required
def task_dashboard(request):
    # Filtering
    tasks = TaskAssignment.objects.select_related('task', 'employee').all()
    # Filter by employee (show all active employees in dropdown)
    employee_id = request.GET.get('employee')
    if employee_id:
        tasks = tasks.filter(employee_id=employee_id)
    # Filter by status
    status = request.GET.get('status')
    if status:
        tasks = tasks.filter(status=status)
    # Filter by date range
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    if from_date:
        tasks = tasks.filter(task__start_date__gte=from_date)
    if to_date:
        tasks = tasks.filter(task__end_date__lte=to_date)
    # Filter by department
    dept = request.GET.get('department')
    if dept:
        tasks = tasks.filter(employee__dept__name=dept)
    # Pagination
    paginator = Paginator(tasks, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    # Stats
    total = tasks.count()
    completed = tasks.filter(status='Completed').count()
    in_progress = tasks.filter(status='In progress').count()
    pending = tasks.filter(status='Pending').count()
    # Show all active employees in filter dropdown
    employees = User.objects.filter(is_employee=True, status=True)
    departments = Department.objects.all()
    return render(request, 'hrm_app/task_dashboard.html', {
        'page_obj': page_obj,
        'employees': employees,
        'departments': departments,
        'total': total,
        'completed': completed,
        'in_progress': in_progress,
        'pending': pending,
    })

@login_required
def task_update(request, pk):
    assignment = get_object_or_404(TaskAssignment, pk=pk)
    if request.method == 'POST':
        form = TaskForm(request.POST, instance=assignment.task)
        assignment_form = TaskAssignmentForm(request.POST, instance=assignment)
        if form.is_valid() and assignment_form.is_valid():
            form.save()
            assignment_form.save()
            messages.success(request, 'Task updated successfully.')
            return redirect('task_dashboard')
    else:
        form = TaskForm(instance=assignment.task)
        assignment_form = TaskAssignmentForm(instance=assignment)
    return render(request, 'hrm_app/task_update.html', {'form': form, 'assignment_form': assignment_form, 'assignment': assignment})

@login_required
def task_delete(request, pk):
    assignment = get_object_or_404(TaskAssignment, pk=pk)
    if request.method == 'POST':
        assignment.delete()
        messages.success(request, 'Task deleted successfully.')
        return redirect('task_dashboard')
    return render(request, 'hrm_app/task_confirm_delete.html', {'assignment': assignment})

@login_required
def task_detail(request, pk):
    assignment = get_object_or_404(TaskAssignment, pk=pk)
    return render(request, 'hrm_app/task_detail.html', {'assignment': assignment})

@login_required
def review_create(request):
    # Only Admin, Manager, TL can add reviews
    if not (request.user.is_superuser or (hasattr(request.user, 'role') and request.user.role and request.user.role.role_name in ['Admin', 'HR', 'Manager', 'Team Leader'])):
        messages.error(request, 'Access denied. Only Admin, HR, Manager, or Team Leader can add reviews.')
        return redirect('review_dashboard')
    if request.method == 'POST':
        form = PerformanceReviewForm(request.POST, user=request.user)
        if form.is_valid():
            review = form.save(commit=False)
            review.reviewed_by = request.user
            review.save()
            messages.success(request, 'Review added successfully.')
            return redirect('review_dashboard')
    else:
        form = PerformanceReviewForm(user=request.user)
    return render(request, 'hrm_app/review_create.html', {'form': form})

@login_required
def review_dashboard(request):
    reviews = PerformanceReview.objects.select_related('employee', 'reviewed_by').all()
    # Filtering
    dept = request.GET.get('department')
    if dept:
        reviews = reviews.filter(employee__dept__name=dept)
    employee_id = request.GET.get('employee')
    if employee_id:
        reviews = reviews.filter(employee_id=employee_id)
    period = request.GET.get('period')
    if period:
        reviews = reviews.filter(review_period=period)
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    if from_date:
        reviews = reviews.filter(review_date__gte=from_date)
    if to_date:
        reviews = reviews.filter(review_date__lte=to_date)
    rating_filter = request.GET.get('rating')
    if rating_filter == '1-5':
        reviews = reviews.filter(rating__gte=1, rating__lte=5)
    elif rating_filter == '6-8':
        reviews = reviews.filter(rating__gte=6, rating__lte=8)
    elif rating_filter == '9+':
        reviews = reviews.filter(rating__gte=9)
    # Pagination
    paginator = Paginator(reviews, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    # Employees for filter dropdown
    employees = User.objects.filter(is_employee=True, status=True)
    departments = Department.objects.all()
    # Statistics
    stats = {
        'monthly': reviews.filter(review_period='Monthly').count(),
        'quarterly': reviews.filter(review_period='Quarterly').count(),
        'annual': reviews.filter(review_period='Annual').count(),
        'rating_1_5': reviews.filter(rating__gte=1, rating__lte=5).count(),
        'rating_6_8': reviews.filter(rating__gte=6, rating__lte=8).count(),
        'rating_9_plus': reviews.filter(rating__gte=9).count(),
    }
    return render(request, 'hrm_app/review_dashboard.html', {
        'page_obj': page_obj,
        'employees': employees,
        'departments': departments,
        'stats': stats,
    })

@login_required
def review_update(request, pk):
    review = get_object_or_404(PerformanceReview, pk=pk)
    if request.method == 'POST':
        form = PerformanceReviewForm(request.POST, instance=review, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Review updated successfully.')
            return redirect('review_dashboard')
    else:
        form = PerformanceReviewForm(instance=review, user=request.user)
    return render(request, 'hrm_app/review_update.html', {'form': form, 'review': review})

@login_required
def review_delete(request, pk):
    review = get_object_or_404(PerformanceReview, pk=pk)
    if request.method == 'POST':
        review.delete()
        messages.success(request, 'Review deleted successfully.')
        return redirect('review_dashboard')
    return render(request, 'hrm_app/review_confirm_delete.html', {'review': review})

@login_required
def review_detail(request, pk):
    review = get_object_or_404(PerformanceReview, pk=pk)
    return render(request, 'hrm_app/review_detail.html', {'review': review})

@login_required
def employee_leave_dashboard(request):
    if not request.user.is_employee:
        messages.error(request, 'Access denied. Employee privileges required.')
        return redirect('employee_dashboard')
    # Get leave quotas for the employee
    quotas = LeaveQuota.objects.filter(employee=request.user)
    quota_dict = {q.leave_type: q for q in quotas}
    # Get all leaves for the employee
    leaves = Leave.objects.filter(employee=request.user).order_by('-start_date')
    return render(request, 'hrm_app/leave_dashboard.html', {
        'quota_dict': quota_dict,
        'leaves': leaves,
    })

@login_required
def apply_leave(request):
    if not request.user.is_employee:
        messages.error(request, 'Access denied. Employee privileges required.')
        return redirect('employee_dashboard')
    if request.method == 'POST':
        form = LeaveForm(request.POST)
        if form.is_valid():
            leave = form.save(commit=False)
            leave.employee = request.user
            # Calculate total_days
            leave.total_days = (leave.end_date - leave.start_date).days + 1
            leave.save()
            messages.success(request, 'Leave applied successfully!')
            return redirect('employee_leave_dashboard')
    else:
        form = LeaveForm()
    return render(request, 'hrm_app/leave_form.html', {'form': form, 'title': 'Apply Leave'})

@login_required
def edit_leave(request, leave_id):
    leave = get_object_or_404(Leave, pk=leave_id, employee=request.user)
    if not leave.is_editable():
        messages.error(request, 'You can only edit pending leaves.')
        return redirect('employee_leave_dashboard')
    if request.method == 'POST':
        form = LeaveForm(request.POST, instance=leave)
        if form.is_valid():
            leave = form.save(commit=False)
            leave.total_days = (leave.end_date - leave.start_date).days + 1
            leave.save()
            messages.success(request, 'Leave updated successfully!')
            return redirect('employee_leave_dashboard')
    else:
        form = LeaveForm(instance=leave)
    return render(request, 'hrm_app/leave_form.html', {'form': form, 'title': 'Update Leave'})

def admin_or_hr(user):
    return user.is_superuser or (hasattr(user, 'role') and user.role and user.role.role_name in ['Admin', 'HR'])

@user_passes_test(admin_or_hr)
def admin_leave_dashboard(request):
    if request.method == 'POST':
        leave_id = request.POST.get('leave_id')
        action = request.POST.get('action')
        leave = get_object_or_404(Leave, pk=leave_id)
        if action == 'approve':
            leave.status = 'approved'
            leave.approved_by = request.user
            leave.save()
            messages.success(request, f'Leave for {leave.employee} approved.')
        elif action == 'reject':
            leave.status = 'rejected'
            leave.approved_by = request.user
            leave.save()
            messages.warning(request, f'Leave for {leave.employee} rejected.')
        return redirect('admin_leave_dashboard')
    leaves = Leave.objects.select_related('employee').all().order_by('-start_date')
    return render(request, 'hrm_app/admin_leave_dashboard.html', {'leaves': leaves})

@user_passes_test(admin_or_hr)
def approve_leave(request, leave_id):
    leave = Leave.objects.get(pk=leave_id)
    if leave.status == 'pending':
        leave.status = 'approved'
        leave.approved_by = request.user
        leave.save()
    return redirect('admin_leave_dashboard')

@user_passes_test(admin_or_hr)
def reject_leave(request, leave_id):
    leave = Leave.objects.get(pk=leave_id)
    if leave.status == 'pending':
        leave.status = 'rejected'
        leave.approved_by = request.user
        leave.save()
    return redirect('admin_leave_dashboard')