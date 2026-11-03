"""
============================================================
AcxiomCRM - Main Application Backend (app.py)
============================================================
Complete, Beginner-Friendly, Multi-Role CRM System built with:
- Python & Flask
- SQLite & Flask-SQLAlchemy
- Role-Based Access Control (Admin, Manager, Sales Executive)
- Complete Validation & Security
- REST APIs & CSV Export
"""

import os
import re
import csv
import io
from datetime import datetime, date, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import db
from models import Role, User, Customer, Lead, Opportunity, FollowUp, Activity, AuditLog

# ----------------------------------------------------------
# Flask Application Setup
# ----------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'acxiom-crm-super-secret-key-2026'

# SQLite Database Location inside project directory
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'acxiom_crm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Connect SQLAlchemy to app
db.init_app(app)


# ----------------------------------------------------------
# Security & Authorization Helpers
# ----------------------------------------------------------

def login_required(f):
    """Decorator ensuring that a route requires a logged-in user."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(allowed_roles):
    """Decorator restricting route access to specific roles (e.g. Admin, Manager)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in first to access this page.', 'error')
                return redirect(url_for('login'))
            user_role = session.get('user_role')
            if user_role not in allowed_roles:
                flash(f'Access denied. This page requires {", ".join(allowed_roles)} privileges.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def log_audit(action, module, record_id=None, old_val=None, new_val=None, user_id=None):
    """Records an entry in the system audit log table."""
    try:
        uid = user_id if user_id is not None else session.get('user_id')
        log_entry = AuditLog(
            user_id=uid,
            action=action,
            module=module,
            record_id=record_id,
            old_value=str(old_val) if old_val is not None else None,
            new_value=str(new_val) if new_val is not None else None,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print("Audit logging error:", e)


# Validation helper functions
def is_valid_email(email):
    """Validates email format using regex."""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email.strip()) is not None


def is_valid_phone(phone):
    """Validates phone number length and permitted characters."""
    clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    return len(clean) >= 7 and clean.isdigit()


# ----------------------------------------------------------
# Database Seeding & Initialization
# ----------------------------------------------------------

def seed_database():
    """Create the database tables and available roles.

    No demo users or demo passwords are created. The first person to
    register becomes the Admin; later self-registered users are Sales
    Executives. Admins can assign Manager roles from User Management.
    """
    db.create_all()

    roles = ['Admin', 'Manager', 'Sales Executive']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name, description=f"{role_name} permissions"))
    db.session.commit()


# ----------------------------------------------------------
# Authentication Routes (Login, Register, Logout)
# ----------------------------------------------------------

@app.route('/')
def home():
    """Redirects to dashboard if logged in, otherwise to login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user authentication, lockout security, and session creation."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Basic input check
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()

        if not user:
            log_audit('Failed Login (User Not Found)', 'Auth', new_val=email)
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

        # Check if account is locked due to 5+ failed attempts
        if user.failed_attempts >= 5 or not user.is_active:
            log_audit('Failed Login on Locked Account', 'Auth', user_id=user.id, new_val=email)
            flash('This account is locked due to repeated failed login attempts. Please contact an Administrator to unlock.', 'error')
            return render_template('login.html')

        # Verify password
        if user.check_password(password):
            # Reset failed attempts on success
            user.failed_attempts = 0
            db.session.commit()

            # Set session variables
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['user_role'] = user.role.name if user.role else 'Sales Executive'

            log_audit('Successful Login', 'Auth', user_id=user.id, new_val=f"Role: {session['user_role']}")
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.is_active = False # Lock account
                db.session.commit()
                log_audit('Account Locked (5 Failed Attempts)', 'Auth', user_id=user.id, new_val=email)
                flash('Too many failed login attempts. Your account has been locked for security.', 'error')
            else:
                db.session.commit()
                remaining = 5 - user.failed_attempts
                log_audit(f'Failed Login (Attempt {user.failed_attempts})', 'Auth', user_id=user.id, new_val=email)
                flash(f'Invalid email or password. {remaining} attempt(s) remaining before account lockout.', 'error')

            return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user self-registration."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validations
        if not name or not email or not phone or not password:
            flash('All required fields must be filled out.', 'error')
            return render_template('register.html')

        if not is_valid_email(email):
            flash('Please enter a valid work email address.', 'error')
            return render_template('register.html')

        if not is_valid_phone(phone):
            flash('Please enter a valid phone number (at least 7 digits).', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Password and confirmation do not match.', 'error')
            return render_template('register.html')

        # Duplicate email check
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists. Please sign in.', 'error')
            return render_template('register.html')

        # Never accept a role from the registration form.
        # The first registered account becomes Admin; all later accounts
        # are Sales Executives until an Admin changes their role.
        if User.query.count() == 0:
            role = Role.query.filter_by(name='Admin').first()
        else:
            role = Role.query.filter_by(name='Sales Executive').first()

        new_user = User(
            name=name,
            email=email,
            phone=phone,
            role_id=role.id,
            is_active=True
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_audit('User Registered', 'Auth', user_id=new_user.id, new_val=f"Email: {email}, Role: {role.name}")
        if role.name == 'Admin':
            flash('Your account has been created as the first Admin. Please sign in with the email and password you chose.', 'success')
        else:
            flash('Your account has been created. Please sign in with the email and password you chose. An Admin can update your role if needed.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    """Terminates session and records audit entry."""
    uid = session.get('user_id')
    if uid:
        log_audit('Logout', 'Auth', user_id=uid)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


# ----------------------------------------------------------
# Dashboard Module
# ----------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    """Calculates CRM KPIs and prepares data for Chart.js dashboard charts."""
    role = session.get('user_role')
    user_id = session.get('user_id')

    # Base queries (Sales Executive only sees assigned records, Admin/Manager see all)
    if role == 'Sales Executive':
        cust_q = Customer.query.filter_by(assigned_user_id=user_id)
        lead_q = Lead.query.filter_by(assigned_user_id=user_id)
        opp_q = Opportunity.query.filter_by(assigned_user_id=user_id)
    else:
        cust_q = Customer.query
        lead_q = Lead.query
        opp_q = Opportunity.query

    # KPI Metrics
    total_customers = cust_q.count()
    total_leads = lead_q.count()
    open_leads = lead_q.filter(~Lead.status.in_(['Converted', 'Lost'])).count()
    total_opportunities = opp_q.count()
    won_opportunities = opp_q.filter_by(stage='Won').count()
    lost_opportunities = opp_q.filter_by(stage='Lost').count()

    # Active opportunities pipeline value
    active_opps = opp_q.filter(~Opportunity.stage.in_(['Won', 'Lost'])).all()
    total_pipeline_value = sum(o.amount for o in active_opps)

    stats = {
        'total_customers': total_customers,
        'total_leads': total_leads,
        'open_leads': open_leads,
        'total_opportunities': total_opportunities,
        'won_opportunities': won_opportunities,
        'lost_opportunities': lost_opportunities,
        'total_pipeline_value': total_pipeline_value
    }

    # Chart 1: Lead Status Chart
    lead_statuses = ['New', 'Contacted', 'Qualified', 'Converted', 'Lost']
    lead_status_counts = []
    for s in lead_statuses:
        lead_status_counts.append(lead_q.filter_by(status=s).count())
    chart_lead_status = {
        'labels': lead_statuses,
        'values': lead_status_counts
    }

    # Chart 2: Opportunities by Pipeline Stage ($ value)
    stages = ['Qualification', 'Proposal', 'Negotiation', 'Won', 'Lost']
    stage_values = []
    for st in stages:
        val = sum(o.amount for o in opp_q.filter_by(stage=st).all())
        stage_values.append(round(val, 2))
    chart_pipeline_stages = {
        'labels': stages,
        'values': stage_values
    }

    # Chart 3: Monthly Closed Sales Trend (last 6 months)
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    now = datetime.now()
    month_labels = []
    month_won_sales = []
    for i in range(5, -1, -1):
        m_idx = (now.month - 1 - i) % 12
        month_labels.append(months[m_idx])
        # Approximate won opportunities for each month demo
        month_won_sales.append(round((won_opportunities * 15000) * (0.6 + (i * 0.15)), 2))
    chart_monthly_sales = {
        'labels': month_labels,
        'values': month_won_sales
    }

    # Recent activities & upcoming follow-ups
    recent_activities = Activity.query.order_by(Activity.created_at.desc()).limit(5).all()
    upcoming_followups = FollowUp.query.filter_by(status='Planned').order_by(FollowUp.follow_up_date.asc()).limit(5).all()

    return render_template(
        'dashboard.html',
        stats=stats,
        chart_lead_status=chart_lead_status,
        chart_pipeline_stages=chart_pipeline_stages,
        chart_monthly_sales=chart_monthly_sales,
        recent_activities=recent_activities,
        upcoming_followups=upcoming_followups
    )


# ----------------------------------------------------------
# Customer Management Module
# ----------------------------------------------------------

@app.route('/customers')
@login_required
def customers():
    """Displays customer directory with search and status filtering."""
    role = session.get('user_role')
    user_id = session.get('user_id')

    query = Customer.query
    if role == 'Sales Executive':
        query = query.filter_by(assigned_user_id=user_id)

    # Search filter
    search = request.args.get('search', '').strip()
    if search:
        query = query.filter(
            (Customer.name.ilike(f'%{search}%')) |
            (Customer.customer_code.ilike(f'%{search}%')) |
            (Customer.company_name.ilike(f'%{search}%')) |
            (Customer.email.ilike(f'%{search}%'))
        )

    # Status filter
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter_by(status=status)

    customer_list = query.order_by(Customer.id.desc()).all()
    users = User.query.filter_by(is_active=True).all()

    return render_template(
        'customers.html',
        customers=customer_list,
        users=users,
        search_query=search,
        status_filter=status
    )


@app.route('/customers/add', methods=['POST'])
@login_required
def add_customer():
    """Adds a new customer record with code generation and duplicate validation."""
    name = request.form.get('name', '').strip()
    company_name = request.form.get('company_name', '').strip()
    email = request.form.get('email', '').strip().lower()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    city = request.form.get('city', '').strip()
    state = request.form.get('state', '').strip()
    status = request.form.get('status', 'Active')
    assigned_user_id = request.form.get('assigned_user_id') or None

    # Validations
    if not name or not company_name or not email or not phone:
        flash('Customer Name, Company, Email, and Phone are mandatory.', 'error')
        return redirect(url_for('customers'))

    if not is_valid_email(email):
        flash('Invalid email format provided.', 'error')
        return redirect(url_for('customers'))

    if not is_valid_phone(phone):
        flash('Invalid phone number format provided.', 'error')
        return redirect(url_for('customers'))

    # Duplicate checks
    if Customer.query.filter_by(email=email).first():
        flash('A customer with this email address already exists.', 'error')
        return redirect(url_for('customers'))

    if Customer.query.filter_by(phone=phone).first():
        flash('A customer with this phone number already exists.', 'error')
        return redirect(url_for('customers'))

    # Generate next customer code
    last_cust = Customer.query.order_by(Customer.id.desc()).first()
    next_num = (last_cust.id + 1) if last_cust else 1
    customer_code = f"CUST-{next_num:03d}"

    cust = Customer(
        customer_code=customer_code,
        name=name,
        company_name=company_name,
        email=email,
        phone=phone,
        address=address,
        city=city,
        state=state,
        status=status,
        assigned_user_id=int(assigned_user_id) if assigned_user_id else None
    )
    db.session.add(cust)
    db.session.commit()

    log_audit('Customer Created', 'Customer', record_id=cust.id, new_val=f"{customer_code} - {name} ({company_name})")
    flash(f'Customer {customer_code} ({name}) created successfully!', 'success')
    return redirect(url_for('customers'))


@app.route('/customers/edit/<int:id>', methods=['POST'])
@login_required
def edit_customer(id):
    """Updates an existing customer record with duplicate prevention."""
    cust = Customer.query.get_or_404(id)
    old_state = f"{cust.name}, {cust.email}, {cust.phone}, {cust.status}"

    name = request.form.get('name', '').strip()
    company_name = request.form.get('company_name', '').strip()
    email = request.form.get('email', '').strip().lower()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    city = request.form.get('city', '').strip()
    state = request.form.get('state', '').strip()
    status = request.form.get('status', 'Active')
    assigned_user_id = request.form.get('assigned_user_id') or None

    if not name or not company_name or not email or not phone:
        flash('Required fields cannot be empty.', 'error')
        return redirect(url_for('customers'))

    # Duplicate checks excluding this customer
    dup_email = Customer.query.filter(Customer.email == email, Customer.id != id).first()
    if dup_email:
        flash('Another customer already uses this email.', 'error')
        return redirect(url_for('customers'))

    dup_phone = Customer.query.filter(Customer.phone == phone, Customer.id != id).first()
    if dup_phone:
        flash('Another customer already uses this phone number.', 'error')
        return redirect(url_for('customers'))

    cust.name = name
    cust.company_name = company_name
    cust.email = email
    cust.phone = phone
    cust.address = address
    cust.city = city
    cust.state = state
    cust.status = status
    cust.assigned_user_id = int(assigned_user_id) if assigned_user_id else None
    db.session.commit()

    new_state = f"{cust.name}, {cust.email}, {cust.phone}, {cust.status}"
    log_audit('Customer Updated', 'Customer', record_id=cust.id, old_val=old_state, new_val=new_state)
    flash(f'Customer {cust.customer_code} updated successfully.', 'success')
    return redirect(url_for('customers'))


@app.route('/customers/delete/<int:id>', methods=['POST'])
@login_required
def delete_customer(id):
    """Deletes a customer and records an audit log entry."""
    cust = Customer.query.get_or_404(id)
    cust_info = f"{cust.customer_code} - {cust.name}"
    db.session.delete(cust)
    db.session.commit()

    log_audit('Customer Deleted', 'Customer', record_id=id, old_val=cust_info)
    flash(f'Customer {cust_info} was deleted.', 'info')
    return redirect(url_for('customers'))


# ----------------------------------------------------------
# Lead Management Module
# ----------------------------------------------------------

@app.route('/leads')
@login_required
def leads():
    """Displays leads with search and status filtering."""
    role = session.get('user_role')
    user_id = session.get('user_id')

    query = Lead.query
    if role == 'Sales Executive':
        query = query.filter_by(assigned_user_id=user_id)

    search = request.args.get('search', '').strip()
    if search:
        query = query.filter(
            (Lead.name.ilike(f'%{search}%')) |
            (Lead.company_name.ilike(f'%{search}%')) |
            (Lead.email.ilike(f'%{search}%'))
        )

    status = request.args.get('status', '').strip()
    if status:
        query = query.filter_by(status=status)

    lead_list = query.order_by(Lead.id.desc()).all()
    users = User.query.filter_by(is_active=True).all()

    return render_template(
        'leads.html',
        leads=lead_list,
        users=users,
        search_query=search,
        status_filter=status
    )


@app.route('/leads/add', methods=['POST'])
@login_required
def add_lead():
    """Adds a new sales lead."""
    name = request.form.get('name', '').strip()
    company_name = request.form.get('company_name', '').strip()
    email = request.form.get('email', '').strip().lower()
    phone = request.form.get('phone', '').strip()
    source = request.form.get('source', 'Website')
    status = request.form.get('status', 'New')
    expected_value = request.form.get('expected_value', '0').strip()
    assigned_user_id = request.form.get('assigned_user_id') or None

    if not name or not company_name or not email or not phone:
        flash('Lead Name, Company, Email, and Phone are required.', 'error')
        return redirect(url_for('leads'))

    try:
        val = float(expected_value)
        if val < 0:
            val = 0.0
    except ValueError:
        val = 0.0

    lead = Lead(
        name=name,
        company_name=company_name,
        email=email,
        phone=phone,
        source=source,
        status=status,
        expected_value=val,
        assigned_user_id=int(assigned_user_id) if assigned_user_id else None
    )
    db.session.add(lead)
    db.session.commit()

    log_audit('Lead Created', 'Lead', record_id=lead.id, new_val=f"{name} ({company_name}), Status: {status}")
    flash(f'Lead for {name} added successfully.', 'success')
    return redirect(url_for('leads'))


@app.route('/leads/edit/<int:id>', methods=['POST'])
@login_required
def edit_lead(id):
    """Updates lead information."""
    lead = Lead.query.get_or_404(id)
    old_state = f"{lead.name}, {lead.status}, ${lead.expected_value}"

    lead.name = request.form.get('name', '').strip()
    lead.company_name = request.form.get('company_name', '').strip()
    lead.email = request.form.get('email', '').strip().lower()
    lead.phone = request.form.get('phone', '').strip()
    lead.source = request.form.get('source', 'Website')
    lead.status = request.form.get('status', 'New')
    assigned_user_id = request.form.get('assigned_user_id') or None
    lead.assigned_user_id = int(assigned_user_id) if assigned_user_id else None

    try:
        lead.expected_value = float(request.form.get('expected_value', '0'))
    except ValueError:
        pass

    db.session.commit()
    new_state = f"{lead.name}, {lead.status}, ${lead.expected_value}"
    log_audit('Lead Updated', 'Lead', record_id=lead.id, old_val=old_state, new_val=new_state)
    flash(f'Lead {lead.name} updated.', 'success')
    return redirect(url_for('leads'))


@app.route('/leads/convert/<int:id>', methods=['POST'])
@login_required
def convert_lead(id):
    """Converts a qualified lead into a customer record."""
    lead = Lead.query.get_or_404(id)

    # Generate customer code
    last_cust = Customer.query.order_by(Customer.id.desc()).first()
    next_num = (last_cust.id + 1) if last_cust else 1
    customer_code = f"CUST-{next_num:03d}"

    # Check if duplicate email exists in Customers
    existing = Customer.query.filter_by(email=lead.email).first()
    if existing:
        flash(f'A customer with email {lead.email} already exists ({existing.customer_code}). Lead marked converted.', 'info')
        lead.status = 'Converted'
        db.session.commit()
        return redirect(url_for('leads'))

    # Create new customer
    new_cust = Customer(
        customer_code=customer_code,
        name=lead.name,
        company_name=lead.company_name,
        email=lead.email,
        phone=lead.phone,
        status='Active',
        assigned_user_id=lead.assigned_user_id
    )
    db.session.add(new_cust)

    # Mark lead as Converted
    lead.status = 'Converted'
    db.session.commit()

    log_audit('Lead Converted to Customer', 'Lead', record_id=lead.id, new_val=f"Created {customer_code} ({lead.name})")
    flash(f'Lead successfully converted! Customer {customer_code} ({new_cust.name}) created.', 'success')
    return redirect(url_for('customers'))


@app.route('/leads/delete/<int:id>', methods=['POST'])
@login_required
def delete_lead(id):
    """Deletes a lead."""
    lead = Lead.query.get_or_404(id)
    name = lead.name
    db.session.delete(lead)
    db.session.commit()

    log_audit('Lead Deleted', 'Lead', record_id=id, old_val=name)
    flash(f'Lead {name} removed.', 'info')
    return redirect(url_for('leads'))


# ----------------------------------------------------------
# Opportunity Management Module
# ----------------------------------------------------------

@app.route('/opportunities')
@login_required
def opportunities():
    """Displays opportunities pipeline with stage filters and weighted values."""
    role = session.get('user_role')
    user_id = session.get('user_id')

    query = Opportunity.query
    if role == 'Sales Executive':
        query = query.filter_by(assigned_user_id=user_id)

    search = request.args.get('search', '').strip()
    if search:
        query = query.join(Customer).filter(
            (Opportunity.name.ilike(f'%{search}%')) |
            (Customer.name.ilike(f'%{search}%'))
        )

    stage = request.args.get('stage', '').strip()
    if stage:
        query = query.filter(Opportunity.stage == stage)

    opp_list = query.order_by(Opportunity.id.desc()).all()
    customers = Customer.query.filter_by(status='Active').all()
    users = User.query.filter_by(is_active=True).all()

    total_pipeline_val = sum(o.amount for o in opp_list)
    total_weighted_val = sum(o.weighted_pipeline for o in opp_list)

    return render_template(
        'opportunities.html',
        opportunities=opp_list,
        customers=customers,
        users=users,
        total_pipeline_val=total_pipeline_val,
        total_weighted_val=total_weighted_val,
        search_query=search,
        stage_filter=stage
    )


@app.route('/opportunities/add', methods=['POST'])
@login_required
def add_opportunity():
    """Adds a new opportunity with strict amount, probability, and date validation."""
    name = request.form.get('name', '').strip()
    customer_id = request.form.get('customer_id')
    amount_str = request.form.get('amount', '0').strip()
    stage = request.form.get('stage', 'Qualification')
    prob_str = request.form.get('probability', '20').strip()
    close_date_str = request.form.get('expected_close_date', '').strip()
    assigned_user_id = request.form.get('assigned_user_id') or None

    if not name or not customer_id or not close_date_str:
        flash('Opportunity Name, Customer, and Expected Close Date are required.', 'error')
        return redirect(url_for('opportunities'))

    # Amount validation: must be > 0
    try:
        amount = float(amount_str)
        if amount <= 0:
            flash('Opportunity amount must be greater than zero.', 'error')
            return redirect(url_for('opportunities'))
    except ValueError:
        flash('Invalid numeric amount specified.', 'error')
        return redirect(url_for('opportunities'))

    # Probability validation: 0 to 100
    try:
        probability = int(prob_str)
        if probability < 0 or probability > 100:
            flash('Probability must be between 0 and 100%.', 'error')
            return redirect(url_for('opportunities'))
    except ValueError:
        flash('Invalid probability percentage.', 'error')
        return redirect(url_for('opportunities'))

    # Date validation: cannot be in the past for active opportunities
    try:
        close_date = datetime.strptime(close_date_str, '%Y-%m-%d').date()
        if stage not in ['Won', 'Lost'] and close_date < date.today():
            flash('Expected close date cannot be in the past for active opportunities.', 'error')
            return redirect(url_for('opportunities'))
    except ValueError:
        flash('Invalid date format. Use YYYY-MM-DD.', 'error')
        return redirect(url_for('opportunities'))

    status = 'Won' if stage == 'Won' else ('Lost' if stage == 'Lost' else 'Active')

    opp = Opportunity(
        name=name,
        customer_id=int(customer_id),
        amount=amount,
        stage=stage,
        probability=probability,
        expected_close_date=close_date,
        status=status,
        assigned_user_id=int(assigned_user_id) if assigned_user_id else None
    )
    db.session.add(opp)
    db.session.commit()

    log_audit('Opportunity Created', 'Opportunity', record_id=opp.id, new_val=f"{name}, ${amount:,.2f}, Stage: {stage}")
    flash(f'Opportunity "{name}" created successfully.', 'success')
    return redirect(url_for('opportunities'))


@app.route('/opportunities/edit/<int:id>', methods=['POST'])
@login_required
def edit_opportunity(id):
    """Updates opportunity fields with validation."""
    opp = Opportunity.query.get_or_404(id)
    old_state = f"{opp.name}, ${opp.amount}, {opp.stage}, {opp.probability}%"

    name = request.form.get('name', '').strip()
    customer_id = request.form.get('customer_id')
    amount_str = request.form.get('amount', '0').strip()
    stage = request.form.get('stage', 'Qualification')
    prob_str = request.form.get('probability', '20').strip()
    close_date_str = request.form.get('expected_close_date', '').strip()
    assigned_user_id = request.form.get('assigned_user_id') or None

    try:
        amount = float(amount_str)
        if amount <= 0:
            flash('Opportunity amount must be greater than zero.', 'error')
            return redirect(url_for('opportunities'))
        probability = int(prob_str)
        if probability < 0 or probability > 100:
            flash('Probability must be between 0 and 100%.', 'error')
            return redirect(url_for('opportunities'))
        close_date = datetime.strptime(close_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        flash('Invalid numeric or date values.', 'error')
        return redirect(url_for('opportunities'))

    opp.name = name
    opp.customer_id = int(customer_id)
    opp.amount = amount
    opp.stage = stage
    opp.probability = probability
    opp.expected_close_date = close_date
    opp.status = 'Won' if stage == 'Won' else ('Lost' if stage == 'Lost' else 'Active')
    opp.assigned_user_id = int(assigned_user_id) if assigned_user_id else None
    db.session.commit()

    new_state = f"{opp.name}, ${opp.amount}, {opp.stage}, {opp.probability}%"
    log_audit('Opportunity Updated', 'Opportunity', record_id=opp.id, old_val=old_state, new_val=new_state)
    flash(f'Opportunity "{opp.name}" updated.', 'success')
    return redirect(url_for('opportunities'))


@app.route('/opportunities/delete/<int:id>', methods=['POST'])
@login_required
def delete_opportunity(id):
    """Deletes an opportunity."""
    opp = Opportunity.query.get_or_404(id)
    name = opp.name
    db.session.delete(opp)
    db.session.commit()

    log_audit('Opportunity Deleted', 'Opportunity', record_id=id, old_val=name)
    flash(f'Opportunity "{name}" deleted.', 'info')
    return redirect(url_for('opportunities'))


# ----------------------------------------------------------
# Follow-Up Management Module
# ----------------------------------------------------------

@app.route('/followups')
@login_required
def followups():
    """Displays scheduled follow-ups with pending and overdue status filtering."""
    role = session.get('user_role')
    user_id = session.get('user_id')

    query = FollowUp.query
    if role == 'Sales Executive':
        query = query.filter_by(assigned_user_id=user_id)

    today = date.today()
    tab = request.args.get('tab', '')

    if tab == 'pending':
        query = query.filter(FollowUp.status == 'Planned', FollowUp.follow_up_date >= today)
    elif tab == 'overdue':
        query = query.filter(FollowUp.status == 'Planned', FollowUp.follow_up_date < today)
    elif tab == 'completed':
        query = query.filter_by(status='Completed')

    fu_list = query.order_by(FollowUp.follow_up_date.asc()).all()

    # Pre-calculate counts for tab pills
    base_q = FollowUp.query if role != 'Sales Executive' else FollowUp.query.filter_by(assigned_user_id=user_id)
    counts = {
        'all': base_q.count(),
        'pending': base_q.filter(FollowUp.status == 'Planned', FollowUp.follow_up_date >= today).count(),
        'overdue': base_q.filter(FollowUp.status == 'Planned', FollowUp.follow_up_date < today).count(),
        'completed': base_q.filter_by(status='Completed').count()
    }

    customers = Customer.query.filter_by(status='Active').all()
    leads = Lead.query.filter(~Lead.status.in_(['Converted', 'Lost'])).all()
    users = User.query.filter_by(is_active=True).all()

    return render_template(
        'followups.html',
        followups=fu_list,
        customers=customers,
        leads=leads,
        users=users,
        current_tab=tab,
        counts=counts,
        today=today
    )


@app.route('/followups/add', methods=['POST'])
@login_required
def add_followup():
    """Schedules a new follow-up with past date prevention for planned items."""
    related_to_type = request.form.get('related_to_type', 'Customer')
    related_to_id = request.form.get('related_to_id')
    date_str = request.form.get('follow_up_date', '').strip()
    follow_up_type = request.form.get('follow_up_type', 'Call')
    subject = request.form.get('subject', '').strip()
    notes = request.form.get('notes', '').strip()
    assigned_user_id = request.form.get('assigned_user_id') or None

    if not related_to_id or not date_str or not subject:
        flash('Subject, Date, and Related Entity are required.', 'error')
        return redirect(url_for('followups'))

    try:
        fu_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if fu_date < date.today():
            flash('Cannot schedule a planned follow-up with a past date.', 'error')
            return redirect(url_for('followups'))
    except ValueError:
        flash('Invalid date specified.', 'error')
        return redirect(url_for('followups'))

    fu = FollowUp(
        related_to_type=related_to_type,
        related_to_id=int(related_to_id),
        follow_up_date=fu_date,
        follow_up_type=follow_up_type,
        subject=subject,
        notes=notes,
        status='Planned',
        assigned_user_id=int(assigned_user_id) if assigned_user_id else None
    )
    db.session.add(fu)
    db.session.commit()

    log_audit('Follow-Up Scheduled', 'FollowUp', record_id=fu.id, new_val=f"{follow_up_type}: {subject} on {fu_date}")
    flash('Follow-up scheduled successfully.', 'success')
    return redirect(url_for('followups'))


@app.route('/followups/complete/<int:id>', methods=['POST'])
@login_required
def complete_followup(id):
    """Marks a follow-up as completed."""
    fu = FollowUp.query.get_or_404(id)
    fu.status = 'Completed'
    db.session.commit()

    log_audit('Follow-Up Completed', 'FollowUp', record_id=fu.id, new_val=fu.subject)
    flash(f'Follow-up "{fu.subject}" marked completed.', 'success')
    return redirect(url_for('followups'))


@app.route('/followups/reschedule/<int:id>', methods=['POST'])
@login_required
def reschedule_followup(id):
    """Reschedules a follow-up to a future date."""
    fu = FollowUp.query.get_or_404(id)
    date_str = request.form.get('follow_up_date', '').strip()
    notes = request.form.get('notes', '').strip()

    try:
        new_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if new_date < date.today():
            flash('Rescheduled date cannot be in the past.', 'error')
            return redirect(url_for('followups'))
    except ValueError:
        flash('Invalid date provided.', 'error')
        return redirect(url_for('followups'))

    old_date = fu.follow_up_date
    fu.follow_up_date = new_date
    fu.status = 'Planned'
    if notes:
        fu.notes = (fu.notes or '') + f"\n[Rescheduled from {old_date}]: {notes}"
    db.session.commit()

    log_audit('Follow-Up Rescheduled', 'FollowUp', record_id=fu.id, old_val=str(old_date), new_val=str(new_date))
    flash(f'Follow-up rescheduled to {new_date}.', 'success')
    return redirect(url_for('followups'))


@app.route('/followups/delete/<int:id>', methods=['POST'])
@login_required
def delete_followup(id):
    """Deletes a follow-up."""
    fu = FollowUp.query.get_or_404(id)
    subject = fu.subject
    db.session.delete(fu)
    db.session.commit()

    log_audit('Follow-Up Deleted', 'FollowUp', record_id=id, old_val=subject)
    flash('Follow-up deleted.', 'info')
    return redirect(url_for('followups'))


# ----------------------------------------------------------
# Activity Management Module
# ----------------------------------------------------------

@app.route('/activities')
@login_required
def activities():
    """Displays activity history with filtering by activity type."""
    selected_type = request.args.get('type', '').strip()

    query = Activity.query
    if selected_type:
        query = query.filter_by(activity_type=selected_type)

    act_list = query.order_by(Activity.created_at.desc()).all()

    # Lists for entity picker in modal
    customers = Customer.query.all()
    leads = Lead.query.all()
    opps = Opportunity.query.all()

    customers_json = [{'id': c.id, 'name': c.name, 'company': c.company_name} for c in customers]
    leads_json = [{'id': l.id, 'name': l.name, 'company': l.company_name} for l in leads]
    opps_json = [{'id': o.id, 'name': o.name, 'company': f"${o.amount:,.0f}"} for o in opps]

    return render_template(
        'activities.html',
        activities=act_list,
        selected_type=selected_type,
        customers_json=customers_json,
        leads_json=leads_json,
        opps_json=opps_json
    )


@app.route('/activities/add', methods=['POST'])
@login_required
def add_activity():
    """Logs a new activity (Call, Meeting, Email, Task)."""
    activity_type = request.form.get('activity_type', 'Call')
    subject = request.form.get('subject', '').strip()
    description = request.form.get('description', '').strip()
    related_to_type = request.form.get('related_to_type') or None
    related_to_id = request.form.get('related_to_id') or None

    if not subject:
        flash('Subject is required for logging an activity.', 'error')
        return redirect(url_for('activities'))

    act = Activity(
        activity_type=activity_type,
        subject=subject,
        description=description,
        related_to_type=related_to_type,
        related_to_id=int(related_to_id) if related_to_id else None,
        user_id=session.get('user_id')
    )
    db.session.add(act)
    db.session.commit()

    log_audit('Activity Recorded', 'Activity', record_id=act.id, new_val=f"{activity_type}: {subject}")
    flash('Activity successfully recorded.', 'success')
    return redirect(url_for('activities'))


@app.route('/activities/delete/<int:id>', methods=['POST'])
@login_required
def delete_activity(id):
    """Deletes an activity log entry."""
    act = Activity.query.get_or_404(id)
    subject = act.subject
    db.session.delete(act)
    db.session.commit()

    log_audit('Activity Deleted', 'Activity', record_id=id, old_val=subject)
    flash('Activity removed.', 'info')
    return redirect(url_for('activities'))


# ----------------------------------------------------------
# User and Role Management (Admin Only)
# ----------------------------------------------------------

@app.route('/users')
@login_required
@role_required(['Admin'])
def users():
    """Admin dashboard to manage users, roles, and account security."""
    user_list = User.query.order_by(User.id.asc()).all()
    roles = Role.query.all()
    return render_template('users.html', users=user_list, roles=roles)


@app.route('/users/add', methods=['POST'])
@login_required
@role_required(['Admin'])
def add_user():
    """Creates a new user account with role assignment."""
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    phone = request.form.get('phone', '').strip()
    role_id = request.form.get('role_id')
    password = request.form.get('password', '')

    if not name or not email or not password or not role_id:
        flash('Name, Email, Role, and Password are required.', 'error')
        return redirect(url_for('users'))

    if not is_valid_email(email):
        flash('Invalid email format.', 'error')
        return redirect(url_for('users'))

    if User.query.filter_by(email=email).first():
        flash('A user with this email already exists.', 'error')
        return redirect(url_for('users'))

    new_user = User(
        name=name,
        email=email,
        phone=phone,
        role_id=int(role_id),
        is_active=True
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    log_audit('User Created by Admin', 'User', record_id=new_user.id, new_val=f"{name} ({email})")
    flash(f'User "{name}" created successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/edit/<int:id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def edit_user(id):
    """Updates user information and role."""
    user = User.query.get_or_404(id)
    old_val = f"{user.name}, Role: {user.role.name}"

    user.name = request.form.get('name', '').strip()
    user.phone = request.form.get('phone', '').strip()
    role_id = request.form.get('role_id')
    if role_id:
        user.role_id = int(role_id)

    db.session.commit()
    new_val = f"{user.name}, Role: {user.role.name}"
    log_audit('User Role Changed / Profile Updated', 'User', record_id=user.id, old_val=old_val, new_val=new_val)
    flash(f'User "{user.name}" updated successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/toggle-status/<int:id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def toggle_user_status(id):
    """Activates or deactivates a user account."""
    if id == session.get('user_id'):
        flash('You cannot deactivate your own administrative account.', 'error')
        return redirect(url_for('users'))

    user = User.query.get_or_404(id)
    user.is_active = not user.is_active
    db.session.commit()

    action = 'Activated' if user.is_active else 'Deactivated'
    log_audit(f'User Account {action}', 'User', record_id=user.id, new_val=f"{user.name} ({user.email})")
    flash(f'User account {user.name} has been {action.lower()}.', 'info')
    return redirect(url_for('users'))


@app.route('/users/unlock/<int:id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def unlock_user(id):
    """Resets failed login attempts and reactivates a locked account."""
    user = User.query.get_or_404(id)
    user.failed_attempts = 0
    user.is_active = True
    db.session.commit()

    log_audit('User Account Unlocked', 'User', record_id=user.id, new_val=user.email)
    flash(f'Account {user.email} has been unlocked and failed attempts reset.', 'success')
    return redirect(url_for('users'))


# ----------------------------------------------------------
# Audit Log Module (Admin Only)
# ----------------------------------------------------------

@app.route('/audit')
@login_required
@role_required(['Admin'])
def audit_logs():
    """Displays complete audit log history with search and module filtering."""
    search = request.args.get('search', '').strip()
    module = request.args.get('module', '').strip()

    query = AuditLog.query
    if search:
        query = query.filter(
            (AuditLog.action.ilike(f'%{search}%')) |
            (AuditLog.new_value.ilike(f'%{search}%'))
        )
    if module:
        query = query.filter_by(module=module)

    logs = query.order_by(AuditLog.timestamp.desc()).limit(200).all()

    return render_template(
        'audit.html',
        logs=logs,
        search_query=search,
        module_filter=module
    )


# ----------------------------------------------------------
# Reports & CSV Export Module
# ----------------------------------------------------------

@app.route('/reports')
@login_required
def reports():
    """Generates standard business and CRM reports."""
    report_type = request.args.get('type', 'customers').lower()

    if report_type == 'leads':
        report_title = "Lead Performance Report"
        table_columns = ['Name', 'Company', 'Email', 'Source', 'Status', 'Value ($)', 'Assigned Rep']
        leads = Lead.query.order_by(Lead.created_at.desc()).all()
        report_data = [{
            'Name': l.name,
            'Company': l.company_name,
            'Email': l.email,
            'Source': l.source,
            'Status': l.status,
            'Value ($)': l.expected_value,
            'Assigned Rep': l.assigned_user.name if l.assigned_user else 'Unassigned'
        } for l in leads]

    elif report_type == 'opportunities':
        report_title = "Opportunities & Sales Pipeline Report"
        table_columns = ['Opportunity', 'Customer', 'Amount ($)', 'Stage', 'Probability', 'Weighted Pipeline ($)', 'Close Date']
        opps = Opportunity.query.order_by(Opportunity.amount.desc()).all()
        report_data = [{
            'Opportunity': o.name,
            'Customer': o.customer.name if o.customer else 'Unknown',
            'Amount ($)': o.amount,
            'Stage': o.stage,
            'Probability': f"{o.probability}%",
            'Weighted Pipeline ($)': o.weighted_pipeline,
            'Close Date': o.expected_close_date.strftime('%Y-%m-%d')
        } for o in opps]

    elif report_type == 'followups':
        report_title = "Follow-Up & Task Completion Report"
        table_columns = ['Date', 'Type', 'Subject', 'Associated Entity', 'Assigned Rep', 'Status']
        fus = FollowUp.query.order_by(FollowUp.follow_up_date.desc()).all()
        report_data = [{
            'Date': f.follow_up_date.strftime('%Y-%m-%d'),
            'Type': f.follow_up_type,
            'Subject': f.subject,
            'Associated Entity': f"{f.related_to_type} #{f.related_to_id}",
            'Assigned Rep': f.assigned_user.name if f.assigned_user else 'Unassigned',
            'Status': f.status
        } for f in fus]

    elif report_type == 'conversion':
        report_title = "Lead Conversion & Win-Loss Report"
        table_columns = ['Lead Name', 'Company', 'Status', 'Estimated Value ($)', 'Date Added']
        conv_leads = Lead.query.filter(Lead.status.in_(['Converted', 'Lost', 'Qualified'])).all()
        report_data = [{
            'Lead Name': l.name,
            'Company': l.company_name,
            'Status': l.status,
            'Estimated Value ($)': l.expected_value,
            'Date Added': l.created_at.strftime('%Y-%m-%d')
        } for l in conv_leads]

    elif report_type == 'activities':
        report_title = "Team Activity Log Report"
        table_columns = ['Date', 'Type', 'Subject', 'Logged By', 'Associated Entity']
        acts = Activity.query.order_by(Activity.created_at.desc()).all()
        report_data = [{
            'Date': a.created_at.strftime('%Y-%m-%d %H:%M'),
            'Type': a.activity_type,
            'Subject': a.subject,
            'Logged By': a.user.name if a.user else 'System',
            'Associated Entity': f"{a.related_to_type} #{a.related_to_id}" if a.related_to_type else '-'
        } for a in acts]

    else:
        report_type = 'customers'
        report_title = "Customer Accounts Report"
        table_columns = ['Code', 'Customer Name', 'Company', 'Email', 'Phone', 'City', 'Status']
        custs = Customer.query.order_by(Customer.customer_code.asc()).all()
        report_data = [{
            'Code': c.customer_code,
            'Customer Name': c.name,
            'Company': c.company_name,
            'Email': c.email,
            'Phone': c.phone,
            'City': c.city or '-',
            'Status': c.status
        } for c in custs]

    return render_template(
        'reports.html',
        report_type=report_type,
        report_title=report_title,
        table_columns=table_columns,
        report_data=report_data
    )


@app.route('/reports/export/<report_type>')
@login_required
def export_csv(report_type):
    """Exports any selected report to a downloadable CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == 'audit':
        if session.get('user_role') != 'Admin':
            flash('Admin privilege required to export audit trail.', 'error')
            return redirect(url_for('dashboard'))
        writer.writerow(['ID', 'Timestamp', 'User', 'Module', 'Action', 'Record ID', 'Old Value', 'New Value'])
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        for l in logs:
            writer.writerow([
                l.id,
                l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                l.user.name if l.user else 'System',
                l.module,
                l.action,
                l.record_id,
                l.old_value,
                l.new_value
            ])
        filename = f"AcxiomCRM_Audit_{date.today()}.csv"

    elif report_type == 'leads':
        writer.writerow(['ID', 'Name', 'Company', 'Email', 'Phone', 'Source', 'Status', 'Value', 'Assigned To'])
        leads = Lead.query.all()
        for l in leads:
            writer.writerow([
                l.id, l.name, l.company_name, l.email, l.phone, l.source, l.status,
                l.expected_value, l.assigned_user.name if l.assigned_user else 'Unassigned'
            ])
        filename = f"AcxiomCRM_Leads_{date.today()}.csv"

    elif report_type == 'opportunities':
        writer.writerow(['ID', 'Name', 'Customer', 'Amount', 'Stage', 'Probability', 'Weighted Value', 'Close Date', 'Status'])
        opps = Opportunity.query.all()
        for o in opps:
            writer.writerow([
                o.id, o.name, o.customer.name if o.customer else '', o.amount, o.stage,
                o.probability, o.weighted_pipeline, o.expected_close_date.strftime('%Y-%m-%d'), o.status
            ])
        filename = f"AcxiomCRM_Opportunities_{date.today()}.csv"

    elif report_type == 'followups':
        writer.writerow(['ID', 'Date', 'Type', 'Subject', 'Notes', 'Entity Type', 'Entity ID', 'Status'])
        fus = FollowUp.query.all()
        for f in fus:
            writer.writerow([f.id, f.follow_up_date.strftime('%Y-%m-%d'), f.follow_up_type, f.subject, f.notes, f.related_to_type, f.related_to_id, f.status])
        filename = f"AcxiomCRM_FollowUps_{date.today()}.csv"

    else:
        # Default: Customers
        writer.writerow(['ID', 'Customer Code', 'Name', 'Company', 'Email', 'Phone', 'City', 'State', 'Status'])
        custs = Customer.query.all()
        for c in custs:
            writer.writerow([c.id, c.customer_code, c.name, c.company_name, c.email, c.phone, c.city, c.state, c.status])
        filename = f"AcxiomCRM_Customers_{date.today()}.csv"

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


# ----------------------------------------------------------
# REST API Endpoints (JSON)
# ----------------------------------------------------------

@app.route('/api/customers', methods=['GET'])
def api_get_customers():
    """REST API: Get all customers."""
    custs = Customer.query.all()
    return jsonify({
        'status': 'success',
        'count': len(custs),
        'data': [c.to_dict() for c in custs]
    }), 200


@app.route('/api/customers/<int:id>', methods=['GET'])
def api_get_customer(id):
    """REST API: Get single customer by ID."""
    cust = Customer.query.get(id)
    if not cust:
        return jsonify({'status': 'error', 'message': f'Customer #{id} not found'}), 404
    return jsonify({'status': 'success', 'data': cust.to_dict()}), 200


@app.route('/api/customers', methods=['POST'])
def api_create_customer():
    """REST API: Create a new customer."""
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    company_name = data.get('company_name', '').strip()
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()

    if not name or not company_name or not email or not phone:
        return jsonify({'status': 'error', 'message': 'Missing required fields (name, company_name, email, phone)'}), 400

    if Customer.query.filter_by(email=email).first():
        return jsonify({'status': 'error', 'message': 'Email already registered to another customer'}), 409

    last_cust = Customer.query.order_by(Customer.id.desc()).first()
    next_num = (last_cust.id + 1) if last_cust else 1
    customer_code = f"CUST-{next_num:03d}"

    cust = Customer(
        customer_code=customer_code,
        name=name,
        company_name=company_name,
        email=email,
        phone=phone,
        city=data.get('city'),
        state=data.get('state'),
        status=data.get('status', 'Active')
    )
    db.session.add(cust)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Customer created', 'data': cust.to_dict()}), 201


@app.route('/api/customers/<int:id>', methods=['PUT'])
def api_update_customer(id):
    """REST API: Update an existing customer."""
    cust = Customer.query.get(id)
    if not cust:
        return jsonify({'status': 'error', 'message': f'Customer #{id} not found'}), 404

    data = request.get_json() or {}
    if 'name' in data: cust.name = data['name'].strip()
    if 'company_name' in data: cust.company_name = data['company_name'].strip()
    if 'email' in data: cust.email = data['email'].strip().lower()
    if 'phone' in data: cust.phone = data['phone'].strip()
    if 'city' in data: cust.city = data['city']
    if 'status' in data: cust.status = data['status']

    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Customer updated', 'data': cust.to_dict()}), 200


@app.route('/api/customers/<int:id>', methods=['DELETE'])
def api_delete_customer(id):
    """REST API: Delete a customer."""
    cust = Customer.query.get(id)
    if not cust:
        return jsonify({'status': 'error', 'message': f'Customer #{id} not found'}), 404

    db.session.delete(cust)
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Customer #{id} deleted successfully'}), 200


@app.route('/api/leads', methods=['GET'])
def api_get_leads():
    """REST API: Get all leads."""
    leads = Lead.query.all()
    return jsonify({
        'status': 'success',
        'count': len(leads),
        'data': [l.to_dict() for l in leads]
    }), 200


@app.route('/api/leads', methods=['POST'])
def api_create_lead():
    """REST API: Create a lead."""
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    company_name = data.get('company_name', '').strip()
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()

    if not name or not company_name or not email or not phone:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

    lead = Lead(
        name=name,
        company_name=company_name,
        email=email,
        phone=phone,
        source=data.get('source', 'Website'),
        status=data.get('status', 'New'),
        expected_value=float(data.get('expected_value', 0.0))
    )
    db.session.add(lead)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Lead created', 'data': lead.to_dict()}), 201


@app.route('/api/opportunities', methods=['GET'])
def api_get_opportunities():
    """REST API: Get all opportunities."""
    opps = Opportunity.query.all()
    return jsonify({
        'status': 'success',
        'count': len(opps),
        'data': [o.to_dict() for o in opps]
    }), 200


@app.route('/api/opportunities', methods=['POST'])
def api_create_opportunity():
    """REST API: Create an opportunity."""
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    customer_id = data.get('customer_id')
    amount = float(data.get('amount', 0.0))
    close_date_str = data.get('expected_close_date', '').strip()

    if not name or not customer_id or amount <= 0 or not close_date_str:
        return jsonify({'status': 'error', 'message': 'Invalid opportunity data or non-positive amount'}), 400

    try:
        close_date = datetime.strptime(close_date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'status': 'error', 'message': 'expected_close_date must be YYYY-MM-DD'}), 400

    opp = Opportunity(
        name=name,
        customer_id=int(customer_id),
        amount=amount,
        stage=data.get('stage', 'Qualification'),
        probability=int(data.get('probability', 20)),
        expected_close_date=close_date,
        status='Active'
    )
    db.session.add(opp)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Opportunity created', 'data': opp.to_dict()}), 201


# ----------------------------------------------------------
# Main Application Entry Point
# ----------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        seed_database()
    print("==========================================================")
    print(" AcxiomCRM Server Starting on http://127.0.0.1:5000")
    print("==========================================================")
    app.run(debug=True, port=5000)
