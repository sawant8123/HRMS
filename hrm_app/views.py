from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django import forms
from .models import Department, Role
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.urls import reverse

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