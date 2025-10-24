# VaultGuardian
VaultGuardian is a secure Flask-based password manager that encrypts credentials, supports multi-factor authentication (TOTP &amp; email OTP), and provides a clean dashboard for adding, editing, and managing sensitive data. Built with Flask, WTForms, and Bootstrap for a modern, user-friendly experience.

#Run the Frontend 
1. Switch to the project folder
2. run "npm run dev"

#Run the database 
1. Run python3 "migrate_data.py" 
2. Run **sqlite3 data/vault.db ** to see what information is stored in the database currently. Potential commands to test out include SELECT * FROM users;


#Future code 
1. Connect the database to the login-page
2. Connect the stored credentials to password manager 

