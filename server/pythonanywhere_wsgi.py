# PythonAnywhere WSGI Configuration
# ==================================
# Copy this content into the WSGI configuration file on PythonAnywhere.
# Location: /var/www/Shazali123_pythonanywhere_com_wsgi.py

import sys
import os

# Add your project directory to the sys.path
project_home = '/home/Shazali123/av-unitest'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables
os.environ['AV_UNITEST_API_KEY'] = 'YOUR_SECURE_API_KEY_HERE'
os.environ['CORS_ORIGINS'] = 'https://Shazali123.pythonanywhere.com'
os.environ['DB_PATH'] = '/home/Shazali123/av-unitest/benchmark.db'

# Import your Flask app
from app import app as application
