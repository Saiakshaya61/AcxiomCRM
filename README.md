# AcxiomCRM – Customer Relationship Management System

## Project Overview

AcxiomCRM is a Customer Relationship Management (CRM) system designed to manage customers, leads, sales opportunities, follow-ups, activities, and users in one place.

The system helps an organization maintain customer information, track sales progress, manage daily activities, and monitor important business operations.

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript

## Mandatory Modules and Features

### 1. Authentication
- User Login
- User Registration
- Logout
- Access Control

### 2. Dashboard
- Total Customers
- Total Leads
- Open Opportunities
- Won Opportunities
- Lost Opportunities
- Sales Pipeline
- Charts

### 3. Customer Management
- Create Customer
- Edit Customer
- View Customer Details
- Delete Customer
- Search Customers

### 4. Lead Management
- Create Lead
- Edit Lead
- View Lead Details
- Delete Lead
- Manage Lead Status
- Lead Conversion

### 5. Opportunity Management
- Create Opportunity
- Edit Opportunity
- View Opportunity Details
- Delete Opportunity
- Sales Pipeline Management

### 6. Follow-Up Management
- Schedule Follow-Up
- Complete Follow-Up
- View Pending Follow-Ups

### 7. Activity Management
- Call
- Meeting
- Email
- Task

### 8. User and Role Management
- Manage Users
- Manage Roles
- Manage Permissions

### 9. Audit Log
- Login Records
- Create Records
- Update Records
- Delete Records

## Project Structure

```text
AcxiomCRM/
│
├── app.py
├── database.py
├── models.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── main.js
│       └── script.js
│
└── templates/
    ├── activities.html
    ├── audit.html
    ├── base.html
    ├── customers.html
    ├── dashboard.html
    ├── index.html
    ├── leads.html
    ├── login.html
    ├── register.html
    ├── opportunities.html
    ├── followups.html
    ├── reports.html
    └── users.html
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Saiakshaya61/AcxiomCRM.git
```

### 2. Open the Project Folder

```bash
cd AcxiomCRM
```

### 3. Install Required Packages

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

### 5. Open in Browser

```text
http://127.0.0.1:5000
```

## Login Instructions

1. Open the application.
2. Register using your own details.
3. Log in using your registered email and password.
4. Access the available CRM features according to your role.

**Security Note:** Do not share passwords, secret keys, or private user information in this public repository.

## Future Enhancements

- Improved reports and analytics
- Advanced search and filtering
- Email notifications
- Enhanced dashboard visualizations
- Additional security features

## Developer

**Sai Akshaya Rupanagudi**

B.Tech – Computer Science and Engineering  
GITAM University, Bengaluru

## GitHub Repository

[AcxiomCRM – GitHub](https://github.com/Saiakshaya61/AcxiomCRM)
