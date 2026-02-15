# Digital Public Issue Reporting & Tracking System (DPIRTS)

A comprehensive web application for citizens to report public issues and track their resolution status.

## Features

- **User Accounts**: Register and login as a citizen.
- **Report Issues**: Submit reports with title, description, location, category, priority, and optional image upload.
- **Dashboard**: Track your reported issues and their status.
- **Admin Panel**: Manage all issues, update status (Submitted -> Under Review -> In Progress -> Resolved -> Closed), and delete reports.
- **Comments**: Discuss issues directly on the report page.
- **Status Timeline**: View the full history of status changes.
- **Responsive Design**: Modern, dark-themed UI that works on all devices.

## Setup & Running

1. **Install Python**: Ensure you have Python installed.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the Application**:
   ```bash
   python app.py
   ```
4. **Access the App**: Open your browser and navigate to `http://localhost:5000`.

## Admin Access

An admin account is automatically created on first run:
- **Email**: `admin@dpirts.gov`
- **Password**: `admin123`

## Technologies

- **Frontend**: HTML5, CSS3 (Custom Design System), JavaScript
- **Backend**: Python (Flask)
- **Database**: SQLite
