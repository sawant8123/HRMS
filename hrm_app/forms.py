from .models import Role, Task, TaskAssignment, User, PerformanceReview
from django import forms

class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['role_name', 'description', 'status']

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Username or Email Address", widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Username or Email Address',
        'required': True
    }))

class OTPForm(forms.Form):
    otp = forms.CharField(label="One Time Password", max_length=6, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'One Time Password',
        'required': True
    }))

class SetNewPasswordForm(forms.Form):
    new_password = forms.CharField(label="New Password", widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'New Password',
        'required': True
    }))
    confirm_password = forms.CharField(label="Confirm New Password", widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Confirm New Password',
        'required': True
    }))

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password')
        password2 = cleaned_data.get('confirm_password')
        if password1 and password2 and password1 != password2:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['task_title', 'task_description', 'task_priority', 'start_date', 'end_date', 'task_type']
        widgets = {
            'task_title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Task Title'}),
            'task_description': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter Task Description', 'rows': 3}),
            'task_priority': forms.Select(attrs={'class': 'form-control'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'task_type': forms.Select(attrs={'class': 'form-control'}),
        }

class TaskAssignmentForm(forms.ModelForm):
    class Meta:
        model = TaskAssignment
        fields = ['employee', 'status']
        widgets = {
            'employee': forms.Select(attrs={'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        # Remove the user filter so all active employees are shown
        super().__init__(*args, **kwargs)
        self.fields['employee'].queryset = User.objects.filter(is_employee=True, status=True) 

class PerformanceReviewForm(forms.ModelForm):
    class Meta:
        model = PerformanceReview
        fields = ['review_title', 'review_date', 'employee', 'review_period', 'rating', 'comments']
        widgets = {
            'review_title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Review Title'}),
            'review_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'employee': forms.Select(attrs={'class': 'form-control'}),
            'review_period': forms.Select(attrs={'class': 'form-control'}),
            'rating': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 10}),
            'comments': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter Comments', 'rows': 2}),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Pop user before calling super
        super().__init__(*args, **kwargs)
        self.fields['employee'].queryset = User.objects.filter(is_employee=True, status=True) 