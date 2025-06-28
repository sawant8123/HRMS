from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Department, Role, User


# Register your models here.

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')
    search_fields = ('name',)
    list_per_page = 10

admin.site.register(Role)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'first_name', 'last_name', 'email', 'mobile', 'dept', 'role', 'is_employee', 'is_superuser', 'status', 'email_verified')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    list_filter = ('dept', 'role', 'is_employee', 'is_superuser', 'status', 'email_verified', 'date_joined')
    ordering = ('id',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'mobile')}),
        ('Employee Details', {'fields': ('dept', 'role', 'reporting_manager', 'date_of_joining')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_employee', 'groups', 'user_permissions')}),
        ('Status', {'fields': ('status', 'email_verified')}),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'first_name', 'last_name', 'email', 'mobile'),
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'date_joined')