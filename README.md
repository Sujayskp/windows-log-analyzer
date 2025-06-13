# 🛡️ Windows Event Log Analyzer

This is a Python tool to analyze Windows Security Event Logs and detect suspicious activity like failed logins, account creation, and more.

## ✅ Features
- Detects failed login attempts (Event ID 4625)
- Detects user creation/deletion
- Saves suspicious events to `report.txt`
- Displays colored output in terminal

## 🛠 Technologies Used
- Python 3
- pywin32
- pandas
- colorama

## ▶️ How to Run
1. Open terminal in the folder.
2. Run `pip install -r requirements.txt`
3. Run the script as admin:
   ```bash
   python analyzer.py
