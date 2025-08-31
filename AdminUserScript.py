"""
This program shows "Authentication" "Roles" and "Access Control".

It also demonstrates "Confidentiality" because only the correct role is allowed to see certain information. 
Admins see the admin report, users see the user report. current_username can be changed to see each report.
"""


# Users and their roles (as if it was a database)
users = {
    "KRYSTAL": "ADMIN",
    "KATE": "USER"
}

# Omitted the passwords and just added the users, can be changed to whoever should have access.
current_username = "KRYSTAL"  

# Authenticates
if current_username in users:
    role = users[current_username]
    print(current_username, "is currently logged in as the", role)
else:
    print("Error: user not found!")
    quit()  # stops program if user is not logged in

print() 


# Admin-only action
def admin_report():
    if role == "ADMIN":
        print("Admin Report: (whatever reports are only for admins).")
    else:
        print("Access Denied - Only admins can view this report.")

# User-only action
def user_report():
    if role == "user":
        print("User Report: (Whatever reports are only for users).")
    else:
        print("Access Denied - Only users can view this report.")

# --- Try both actions ---
print("Looking up admin report:")
admin_report()
print()

print("Looking up user report:")
user_report()