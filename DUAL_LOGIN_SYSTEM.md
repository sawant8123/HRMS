# HRMS Dual Login System

This HRMS (Human Resource Management System) now supports a dual login system with separate authentication for administrators and employees.

## System Overview

### Admin Login
- **URL**: `/admin-login/`
- **Access**: Only superusers (Django admin users)
- **Features**: Full CRUD operations for departments, roles, and employees
- **Dashboard**: Access to all management modules

### Employee Login
- **URL**: `/employee-login/`
- **Access**: Registered employees only
- **Features**: View personal information only
- **Dashboard**: Personal employee dashboard

## Employee Registration Flow

1. **Signup**: Employees can register at `/employee-signup/`
2. **Email Verification**: OTP sent to email for verification
3. **Login**: After verification, employees can login
4. **Dashboard**: View personal information only

## Key Features

### Admin Features
- Create, update, delete departments
- Create, update, delete roles
- Create, update, delete employees
- View all employee information
- Reactivate inactive departments/roles

### Employee Features
- Self-registration with email verification
- View personal information only
- Password reset functionality
- Secure login with email verification

### Security Features
- Email verification required for employees
- OTP-based password reset
- Separate authentication for admins and employees
- Soft delete for data protection

## User Types

### Superuser (Admin)
- `is_superuser = True`
- `is_employee = False`
- Full system access

### Employee
- `is_superuser = False`
- `is_employee = True`
- `email_verified = True/False`
- Limited access to personal data only

## Database Changes

The User model has been updated to inherit from Django's AbstractUser with additional fields:
- `is_employee`: Distinguishes between admin and employee users
- `email_verified`: Tracks email verification status
- `otp`: Stores OTP for email verification
- `otp_created_at`: Tracks OTP expiry

## Email Configuration

The system uses Django's email backend. For development, it's configured to use console backend. For production, configure SMTP settings in `settings.py`.

## URLs

- `/` - Redirects to admin login
- `/admin-login/` - Admin login page
- `/employee-login/` - Employee login page
- `/employee-signup/` - Employee registration
- `/employee-verify-email/<id>/` - Email verification
- `/employee-dashboard/` - Employee dashboard
- `/logout/` - Logout (redirects to admin login)

## Setup Instructions

1. Run migrations: `python manage.py migrate`
2. Create a superuser: `python manage.py createsuperuser`
3. Configure email settings in `settings.py`
4. Start the development server: `python manage.py runserver`

## Notes

- Only verified employees can login
- Password reset is only available for employees
- Admin users must be created via Django admin or command line
- All employee data is soft-deleted (status field) 