from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django import forms
from .models import Department
from django.contrib import messages
from django.contrib.auth import authenticate, login

# Create your views here.

# Inline form inside views.py
class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ['name', 'description']

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
        messages.success(request, "Department marked as inactive.")
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