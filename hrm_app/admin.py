from django.contrib import admin
from .models import Department, Role, User


# Register your models here.

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')
    search_fields = ('name',)
    list_per_page = 10

admin.site.register(Role)

class UserAdmin(admin.ModelAdmin):
    list_display = ('employee_id', 'username', 'first_name', 'last_name', 'email', 'mobile', 'dept', 'role', 'reporting_manager', 'date_of_joining', 'created_at', 'updated_at')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    list_filter = ('dept', 'role', 'date_of_joining')

admin.site.register(User, UserAdmin)