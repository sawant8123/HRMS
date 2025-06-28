from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password

# Create your models here.

class Department(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()

    def __str__(self):
        return self.name

class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)  # True = Active, False = Inactive (soft delete)

    def __str__(self):
        return self.role_name

class User(AbstractUser):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100, unique=True)
    email = models.CharField(max_length=100, unique=True)
    mobile = models.CharField(max_length=100)
    dept = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, related_name='employees')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, related_name='employees')
    reporting_manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subordinates')
    date_of_joining = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)  # True = Active, False = Inactive (soft delete)
    is_employee = models.BooleanField(default=False)  # To distinguish between admin and employee
    email_verified = models.BooleanField(default=False)  # For email verification
    otp = models.CharField(max_length=6, null=True, blank=True)  # For OTP verification
    otp_created_at = models.DateTimeField(null=True, blank=True)  # OTP expiry tracking

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        # Hash password if it's not already hashed
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

class Task(models.Model):
    task_id = models.AutoField(primary_key=True)
    task_title = models.CharField(max_length=100)
    task_description = models.CharField(max_length=300)
    task_priority = models.CharField(max_length=20, choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')])
    start_date = models.DateField()
    end_date = models.DateField()
    task_type = models.CharField(max_length=50, choices=[('Individual', 'Individual'), ('Team', 'Team')])
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.task_title

class TaskAssignment(models.Model):
    assignment_id = models.AutoField(primary_key=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='assignments')
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='task_assignments')
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tasks')
    assigned_date = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('In progress', 'In progress'), ('Completed', 'Completed')], default='Pending')
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.task.task_title} -> {self.employee.username}"

class PerformanceReview(models.Model):
    review_id = models.AutoField(primary_key=True)
    review_title = models.CharField(max_length=100)
    review_date = models.DateField()
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reviews')
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reviews_given')
    review_period = models.CharField(max_length=100, choices=[('Monthly', 'Monthly'), ('Quarterly', 'Quarterly'), ('Annual', 'Annual')])
    rating = models.IntegerField()
    comments = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.review_title} ({self.employee}) - {self.review_period}"