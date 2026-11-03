AcxiomCRM - Updated Registration Version

SETUP (Windows / PowerShell)
1. Extract this ZIP file.
2. Open PowerShell in the extracted AcxiomCRM_Complete folder.
3. Install packages:
   python -m pip install -r requirements.txt
4. Start the application:
   python app.py
5. Open http://127.0.0.1:5000 in your browser.
6. Select "Create an account" and register using your own name, email, phone number, and password.
7. Sign in using the email and password you created.

ACCOUNT / ROLE RULES
- No default demo users or demo passwords are created.
- The FIRST account registered becomes Admin.
- Every later self-registered account becomes Sales Executive.
- An Admin can create users and assign Manager / Sales Executive roles from User & Role Management.
- Users cannot select Admin or Manager during public registration.

DATABASE
- A new SQLite database file (acxiom_crm.db) is created automatically when the application starts.
- To start fresh, stop the server with CTRL+C and delete acxiom_crm.db, then run python app.py again.
- Deleting the database removes all CRM accounts and records. The first person to register after that becomes Admin.

IMPORTANT
- This is an educational local development project. Do not use real sensitive customer data or deploy it publicly without additional security hardening.
- Keep the PowerShell window open while using the application.
