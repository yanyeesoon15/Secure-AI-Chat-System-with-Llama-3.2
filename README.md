# Secure-AI-Chat-System-with-Llama-3.2
Development and implementation code of Secure AI Chat System
Secure AI Chat System

A role-based access control (RBAC) AI chat system built with Flask, SQLite, ChromaDB, and a locally-hosted LLM via Ollama. Features AES-256 encrypted sensitive data, privilege elevation, audit logging, and document management across multiple user roles (Admin, CEO, Manager, Employee).

Key Features
Role-Based Access Control (RBAC) — Admin, CEO, Manager, Employee roles with distinct permissions
AI Chat powered by Llama 3.2 — Locally hosted via Ollama (no external API needed)
AES-256 Encryption — Sensitive fields (salary, IC number, bank account) encrypted at rest
Vector Search (ChromaDB) — Document chunks stored and retrieved semantically
Privilege Elevation — Employees can request temporary higher access levels
Audit Logging — All sensitive actions are logged
Document Management — Upload and classify documents (PDF, DOCX, CSV, XLSX)
Report Generation — Export audit logs and user data as PDF or Excel

Before running this project, install the following:
1. Python 3.10+
Download from python.org and ensure it is added to your PATH.
Verify: bashpython --version

2. Ollama (Local LLM Runtime)
Ollama runs the AI model locally on your machine.
Download from ollama.com and install for your OS.
Verify:ollama --version

3. Llama 3.2 Model
After installing Ollama, pull the Llama 3.2 model: ollama pull llama3.2
This downloads approximately 2 GB. Ensure you have enough disk space.

4. Report Generation code
pip install pycryptodome
pip install flask werkzeug requests openpyxl reportlab PyPDF2 python-docx pycryptodome chromadb
All the file in VS code show like this:
<img width="410" height="495" alt="image" src="https://github.com/user-attachments/assets/0031432d-56d8-4ef8-8815-2bc95ae1c02a" />

Running the Application
Step 1 Start Ollama
Open a terminal and run: ollama serve
Keep this terminal open. Ollama must be running before you start the Flask app.

Step 2 Start the Flask server
In a new terminal (with your virtual environment activated):
You should see output like:
SECURE AI CHAT SYSTEM - WITH DATABASE ENCRYPTION
Default Users:
  admin / admin123 - System Admin
  ceo / ceo123 - CEO
  jason / demo123 - IT Manager
  sarah / demo123 - HR Manager
  ahmad / demo123 - IT Employee
  linda / demo123 - Finance Employee
  
Step 3 Open the app
Go to http://localhost:5000 in your browser.
If cannot, put(/chat) in the back http://localhost:5000/chat

Configuration
The master encryption password is set in app.py:
pythonMASTER_PASSWORD = "admin123"
change http://localhost:5000/chat to http://localhost:5000/view-encrypted to access databases.
All the sensitive data are encrypted using AES-256 encryption and displayed in ciphertext.
Password: admin123
This password allow administrator check plaintext of sensitive data.
The system generate default users and organizational department so user can have a testing.
User can add your own user to test.
All the password of default is : demo123
Administrator username and password: admin/admin123
There have several test documents for user to test in (uploads) document

Troubleshooting
1. AI service is not running error in chat
Make sure ollama serve is running in a separate terminal
2. ModuleNotFoundError on startup
Run pip install -r requirements.txt again inside your virtual environment
3. Port 5000 already in use
Change port=5000 to another port (e.g. 5001) at the bottom of app.py
4. llama3.2 model not found
Run ollama pull llama3.2 and wait for the download to complete
5. Database locked errors
Avoid opening the .db file with another tool while the app is running
6. Automatic revoke function not function
Can wait a while for system to responding and it may take in 20-30 seconds depend on user's hardware
Continue refresh the browser and the function should work.
