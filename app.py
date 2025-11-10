from flask import Flask, render_template, redirect, url_for, flash, request, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import io
import csv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Custom filter for newline to br conversion
@app.template_filter('nl2br')
def nl2br(value):
    if value:
        return value.replace('\n', '<br>\n')
    return ''

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    complaints = db.relationship('Complaint', backref='author', lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
        else:
            complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
        return render_template('dashboard.html', complaints=complaints)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/complaint/new', methods=['GET', 'POST'])
@login_required
def new_complaint():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')
        
        new_complaint = Complaint(
            title=title,
            description=description,
            category=category,
            priority=priority,
            user_id=current_user.id
        )
        db.session.add(new_complaint)
        db.session.commit()
        
        flash('Your complaint has been submitted!', 'success')
        return redirect(url_for('index'))
    return render_template('create_complaint.html')

@app.route('/complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    if not current_user.is_admin and complaint.user_id != current_user.id:
        flash('You do not have permission to view this complaint', 'danger')
        return redirect(url_for('index'))
    return render_template('view_complaint.html', complaint=complaint)

@app.route('/complaint/<int:complaint_id>/update', methods=['GET', 'POST'])
@login_required
def update_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    if complaint.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to update this complaint', 'danger')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        complaint.title = request.form.get('title')
        complaint.description = request.form.get('description')
        complaint.category = request.form.get('category')
        complaint.priority = request.form.get('priority')
        if current_user.is_admin:
            complaint.status = request.form.get('status')
        
        db.session.commit()
        flash('Complaint has been updated!', 'success')
        return redirect(url_for('view_complaint', complaint_id=complaint.id))
        
    return render_template('update_complaint.html', complaint=complaint)

@app.route('/complaint/<int:complaint_id>/delete', methods=['POST'])
@login_required
def delete_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    if complaint.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this complaint', 'danger')
        return redirect(url_for('index'))
        
    db.session.delete(complaint)
    db.session.commit()
    flash('Complaint has been deleted!', 'success')
    return redirect(url_for('index'))

# Download Routes
@app.route('/download/csv')
@login_required
def download_csv():
    if current_user.is_admin:
        complaints = Complaint.query.all()
    else:
        complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Title', 'Description', 'Category', 'Priority', 'Status', 'Created Date', 'Submitted By'])
    
    # Write data
    for complaint in complaints:
        writer.writerow([
            complaint.id,
            complaint.title,
            complaint.description,
            complaint.category or 'General',
            complaint.priority,
            complaint.status,
            complaint.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            complaint.author.username
        ])
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=complaints.csv"
    response.headers["Content-type"] = "text/csv"
    
    return response

# Simplified download route without Excel dependency
@app.route('/download/report')
@login_required
def download_report():
    if current_user.is_admin:
        complaints = Complaint.query.all()
    else:
        complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Title', 'Description', 'Category', 'Priority', 'Status', 'Created Date', 'Submitted By'])
    
    # Write data
    for complaint in complaints:
        writer.writerow([
            complaint.id,
            complaint.title,
            complaint.description,
            complaint.category or 'General',
            complaint.priority,
            complaint.status,
            complaint.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            complaint.author.username
        ])
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=complaints_report.csv"
    response.headers["Content-type"] = "text/csv"
    
    return response

# Create database tables
with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    import os
    # For Render deployment, use the PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    # Use 0.0.0.0 to make it accessible from outside Docker containers
    app.run(host='0.0.0.0', port=port, debug=False)
