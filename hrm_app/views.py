from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django import forms
from .models import Department, Role, User
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.urls import reverse
from django.db.models import Q

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
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'password', 'email', 'mobile', 'dept', 'role', 'reporting_manager', 'date_of_joining']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'password': forms.PasswordInput(attrs={'class': 'form-control'}),
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

# Only allow admin
admin_required = user_passes_test(lambda u: u.is_superuser)

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
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('department_list')  # or your desired page
        else:
            return render(request, 'hrm_app/login.html', {'error': 'Invalid username or password'})

    return render(request, 'hrm_app/login.html')

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

# Only admin or HR (role name 'Admin' or 'HR')
def admin_or_hr_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_superuser or (hasattr(request.user, 'user') and request.user.user.role and request.user.user.role.role_name in ['Admin', 'HR']):
            return view_func(request, *args, **kwargs)
        return redirect('department_list')
    return login_required(_wrapped_view)

@admin_or_hr_required
def employee_list(request):
    search_query = request.GET.get('search', '').strip()
    employees = User.objects.filter(status=True)
    if search_query:
        employees = employees.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(username__icontains=search_query)
        )
    return render(request, 'hrm_app/employee_list.html', {
        'employees': employees,
        'search_query': search_query,
    })

@admin_or_hr_required
def employee_create(request):
    if request.method == 'POST':
        form = InlineUserForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Employee added successfully.')
            return redirect('employee_list')
    else:
        form = InlineUserForm()
    return render(request, 'hrm_app/employee_form.html', {'form': form, 'title': 'Add Employee'})

@admin_or_hr_required
def employee_update(request, pk):
    employee = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form = InlineUserForm(request.POST, instance=employee)
        if form.is_valid():
            form.save()
            messages.success(request, 'Employee updated successfully.')
            return redirect('employee_list')
    else:
        form = InlineUserForm(instance=employee)
    return render(request, 'hrm_app/employee_form.html', {'form': form, 'title': 'Edit Employee'})

@admin_or_hr_required
def employee_delete(request, pk):
    employee = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        employee.status = False  # Soft delete
        employee.save()
        messages.warning(request, 'Employee marked as inactive.')
        return redirect('employee_list')
    return render(request, 'hrm_app/employee_confirm_delete.html', {'employee': employee})