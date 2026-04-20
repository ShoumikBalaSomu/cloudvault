# CloudVault - Secure Cloud Storage Platform
# OS Security/Protection Project
# Main application entry point
# This file sets up the Flask app, registers all blueprints and configures the application

import os
import sys
from flask import Flask, redirect, url_for, session
from database import init_db
from routes.auth import auth_bp
from routes.files import files_bp
from routes.share import share_bp
from routes.admin import admin_bp

app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encrypted_storage')
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloudvault.db')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(files_bp, url_prefix='/api/files')
app.register_blueprint(share_bp, url_prefix='/api/share')
app.register_blueprint(admin_bp, url_prefix='/api/admin')


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))
    return redirect(url_for('auth.login_page'))


@app.before_request
def before_request():
    init_db(app.config['DATABASE'])


if __name__ == '__main__':
    init_db(app.config['DATABASE'])
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
