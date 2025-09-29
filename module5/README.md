# Module 5: Assignment - OWASP Top 10 Code Fix

App showing **login** and **role-based access control** with secure patterns -- hashed passwords, protected routes, safe password reset.

REQUIREMENTS
- flask==3.0.3
- flask-login==0.6.3
- flask-sqlalchemy==3.1.1
- passlib[bcrypt]==1.7.4
- itsdangerous==2.2.0
- argon2-cffi==23.1.0


## Quick start

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows
pip install flask flask-login flask-sqlalchemy passlib[bcrypt] itsdangerous argon2-cffi

# initialize DB + sample users (admin & user)
flask --app app.py init-db

# run
flask --app app.py run  # then open http://127.0.0.1:5000/
```

### Sample accounts
- Admin: `admin@example.com` / `AdminPassw0rd!`
- User:  `user@example.com`  / `UserPassw0rd!`

## Notes
- `@login_required` protects routes.
- `role_required("admin")` decorator enforces role-based access control.
- Passwords stored with Argon2/bcrypt via `passlib`.
- Password reset uses signed, time-limited tokens (see console log for reset link in this demo).
