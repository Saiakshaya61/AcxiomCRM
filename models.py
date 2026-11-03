"""
============================================================
AcxiomCRM - Database Models
============================================================
Defines the SQLite database tables using Flask-SQLAlchemy:
- Role
- User
- Customer
- Lead
- Opportunity
- FollowUp
- Activity
- AuditLog
"""

from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

# ----------------------------------------------------------
# 1. Role Model
# ----------------------------------------------------------
class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False) # Admin, Manager, Sales Executive
    description = db.Column(db.String(200), nullable=True)

    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f"<Role {self.name}>"


# ----------------------------------------------------------
# 2. User Model
# ----------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    customers = db.relationship('Customer', backref='assigned_user', lazy=True)
    leads = db.relationship('Lead', backref='assigned_user', lazy=True)
    opportunities = db.relationship('Opportunity', backref='assigned_user', lazy=True)
    followups = db.relationship('FollowUp', backref='assigned_user', lazy=True)
    activities = db.relationship('Activity', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    def set_password(self, password):
        """Securely hashes and sets the user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Validates the password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'role': self.role.name if self.role else None,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

    def __repr__(self):
        return f"<User {self.email}>"


# ----------------------------------------------------------
# 3. Customer Model
# ----------------------------------------------------------
class Customer(db.Model):
    __tablename__ = 'customers'

    id = db.Column(db.Integer, primary_key=True)
    customer_code = db.Column(db.String(20), unique=True, nullable=False) # e.g. CUST-001
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(80), nullable=True)
    state = db.Column(db.String(80), nullable=True)
    status = db.Column(db.String(20), default='Active', nullable=False) # Active, Inactive
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Relationships
    opportunities = db.relationship('Opportunity', backref='customer', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_code': self.customer_code,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'company_name': self.company_name,
            'address': self.address,
            'city': self.city,
            'state': self.state,
            'status': self.status,
            'created_date': self.created_date.strftime('%Y-%m-%d %H:%M:%S') if self.created_date else None,
            'assigned_user': self.assigned_user.name if self.assigned_user else None,
            'assigned_user_id': self.assigned_user_id
        }

    def __repr__(self):
        return f"<Customer {self.customer_code} - {self.name}>"


# ----------------------------------------------------------
# 4. Lead Model
# ----------------------------------------------------------
class Lead(db.Model):
    __tablename__ = 'leads'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    source = db.Column(db.String(50), default='Website', nullable=False) # Website, Referral, Cold Call, LinkedIn, etc.
    status = db.Column(db.String(30), default='New', nullable=False) # New, Contacted, Qualified, Lost, Converted
    expected_value = db.Column(db.Float, default=0.0, nullable=False)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'company_name': self.company_name,
            'source': self.source,
            'status': self.status,
            'expected_value': self.expected_value,
            'assigned_user': self.assigned_user.name if self.assigned_user else None,
            'assigned_user_id': self.assigned_user_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

    def __repr__(self):
        return f"<Lead {self.name} - {self.status}>"


# ----------------------------------------------------------
# 5. Opportunity Model
# ----------------------------------------------------------
class Opportunity(db.Model):
    __tablename__ = 'opportunities'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    amount = db.Column(db.Float, default=0.0, nullable=False)
    stage = db.Column(db.String(40), default='Qualification', nullable=False) # Qualification, Proposal, Negotiation, Won, Lost
    probability = db.Column(db.Integer, default=10, nullable=False) # 0 to 100
    expected_close_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='Active', nullable=False) # Active, Won, Lost
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def weighted_pipeline(self):
        """Calculates weighted pipeline: Amount * Probability / 100"""
        try:
            return round((float(self.amount) * float(self.probability)) / 100.0, 2)
        except (ValueError, TypeError):
            return 0.0

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'customer_id': self.customer_id,
            'customer_name': self.customer.name if self.customer else None,
            'amount': self.amount,
            'stage': self.stage,
            'probability': self.probability,
            'expected_close_date': self.expected_close_date.strftime('%Y-%m-%d') if self.expected_close_date else None,
            'status': self.status,
            'weighted_pipeline': self.weighted_pipeline,
            'assigned_user': self.assigned_user.name if self.assigned_user else None,
            'assigned_user_id': self.assigned_user_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

    def __repr__(self):
        return f"<Opportunity {self.name} - {self.stage}>"


# ----------------------------------------------------------
# 6. FollowUp Model
# ----------------------------------------------------------
class FollowUp(db.Model):
    __tablename__ = 'followups'

    id = db.Column(db.Integer, primary_key=True)
    related_to_type = db.Column(db.String(20), nullable=False) # 'Customer' or 'Lead'
    related_to_id = db.Column(db.Integer, nullable=False)
    follow_up_date = db.Column(db.Date, nullable=False)
    follow_up_type = db.Column(db.String(30), default='Call', nullable=False) # Call, Meeting, Email, Task
    subject = db.Column(db.String(150), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='Planned', nullable=False) # Planned, Completed, Missed, Cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'related_to_type': self.related_to_type,
            'related_to_id': self.related_to_id,
            'follow_up_date': self.follow_up_date.strftime('%Y-%m-%d') if self.follow_up_date else None,
            'follow_up_type': self.follow_up_type,
            'subject': self.subject,
            'notes': self.notes,
            'assigned_user': self.assigned_user.name if self.assigned_user else None,
            'assigned_user_id': self.assigned_user_id,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

    def __repr__(self):
        return f"<FollowUp {self.subject} - {self.status}>"


# ----------------------------------------------------------
# 7. Activity Model
# ----------------------------------------------------------
class Activity(db.Model):
    __tablename__ = 'activities'

    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(30), nullable=False) # Call, Meeting, Email, Task
    subject = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    related_to_type = db.Column(db.String(30), nullable=True) # Customer, Lead, Opportunity
    related_to_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'activity_type': self.activity_type,
            'subject': self.subject,
            'description': self.description,
            'related_to_type': self.related_to_type,
            'related_to_id': self.related_to_id,
            'user': self.user.name if self.user else None,
            'user_id': self.user_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

    def __repr__(self):
        return f"<Activity {self.activity_type} - {self.subject}>"


# ----------------------------------------------------------
# 8. AuditLog Model
# ----------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False) # e.g. Customer Created, Successful Login, Lead Updated
    module = db.Column(db.String(50), nullable=False) # Auth, Customer, Lead, Opportunity, User, FollowUp
    record_id = db.Column(db.Integer, nullable=True)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.name if self.user else 'System',
            'user_id': self.user_id,
            'action': self.action,
            'module': self.module,
            'record_id': self.record_id,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None
        }

    def __repr__(self):
        return f"<AuditLog {self.action} on {self.module}>"

