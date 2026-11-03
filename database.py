"""
============================================================
AcxiomCRM - Database Connection & Initialization
============================================================
Initializes the Flask-SQLAlchemy database extension.
Separating db instance here prevents circular imports between
app.py and models.py.
"""

from flask_sqlalchemy import SQLAlchemy

# Create the SQLAlchemy object instance
db = SQLAlchemy()

