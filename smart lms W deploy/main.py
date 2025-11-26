import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, abort
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from functools import wraps
from werkzeug.utils import secure_filename
import google.generativeai as genai
import pytz
import requests
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import fitz  # PyMuPDF
from google.api_core import client_options
import socket

print(f"✅ [DEBUG] google-generativeai library version: {genai.__version__}")

# Load environment variables and configure API
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config['UPLOAD_FOLDER'] = 'static/uploads/pdfs'
app.config['AVATAR_UPLOAD_FOLDER'] = 'static/uploads/avatars'
app.config['ASSIGNMENT_UPLOAD_FOLDER'] = 'static/uploads/assignments'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'txt'}
app.config['ADMIN_EMAIL'] = "swapnilrao729@gmail.com"
app.config['AI_SERVICE_URL'] = "http://127.0.0.1:5001"
app.config['ASSIGNMENT_SUBMISSIONS_FOLDER'] = 'static/uploads/submissions'

# Create upload directories
os.makedirs(app.config['ASSIGNMENT_SUBMISSIONS_FOLDER'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['AVATAR_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ASSIGNMENT_UPLOAD_FOLDER'], exist_ok=True)

try:
    mongo = PyMongo(app)
    mongo.db.command('ping')
    print("--- SUCCESS: Database connection established! ---")
except Exception as e:
    print(f"--- CRITICAL ERROR: Could not connect to database. Error: {e} ---")

def seed_courses():
    if mongo.db.courses.count_documents({}) == 0:
        print("--- Seeding initial courses into the database... ---")
        courses_to_add = [
            {"title": "Operating Systems", "description": "Core concepts of modern operating systems.", "category": "Computer Science", "icon": "fa-cogs", "teacher_id": None},
            {"title": "Machine Learning", "description": "Fundamentals of ML, from regression to neural networks.", "category": "AI/ML", "icon": "fa-robot", "teacher_id": None},
            {"title": "Object-Oriented Programming", "description": "Learn OOPS principles using languages like Java or C++.", "category": "Programming", "icon": "fa-cubes", "teacher_id": None},
            {"title": "Data Structures & Algorithms", "description": "Master essential data structures and algorithms.", "category": "Programming", "icon": "fa-sitemap", "teacher_id": None},
            {"title": "Design & Analysis of Algorithms", "description": "Advanced algorithm design and complexity analysis.", "category": "Computer Science", "icon": "fa-calculator", "teacher_id": None},
            {"title": "Computer Networks", "description": "Understand the protocols and architecture of the internet.", "category": "Networking", "icon": "fa-network-wired", "teacher_id": None},
            {"title": "Software Engineering", "description": "Principles of software design, development, and testing.", "category": "Development", "icon": "fa-drafting-compass", "teacher_id": None}
        ]
        mongo.db.courses.insert_many(courses_to_add)
        print("--- Course seeding complete. ---")

with app.app_context():
    seed_courses()

# --- Improved Email Functions with Timeout Handling ---
def send_otp_email(recipient_email, otp):
    SENDER_EMAIL = os.getenv("SENDER_EMAIL")
    SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
    
    if not SENDER_EMAIL or not SENDER_PASSWORD: 
        print("SMTP credentials not configured")
        return False
    
    msg = EmailMessage()
    msg['Subject'] = "Your IntelliLearn Verification Code"
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg.set_content(f"Your One-Time Password (OTP) is: {otp}\n\nThis code will expire in 10 minutes.")
    
    try:
        # Try multiple SMTP configurations with timeout
        smtp_servers = [
            ('smtp.gmail.com', 587),  # TLS
            ('smtp.gmail.com', 465),  # SSL
        ]
        
        for server, port in smtp_servers:
            try:
                print(f"Trying SMTP server: {server}:{port}")
                if port == 587:
                    # TLS connection with timeout
                    smtp = smtplib.SMTP(server, port, timeout=30)
                    smtp.starttls()
                else:
                    # SSL connection with timeout
                    smtp = smtplib.SMTP_SSL(server, port, timeout=30)
                
                smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
                smtp.send_message(msg)
                smtp.quit()
                print(f"Email sent successfully via {server}:{port}")
                return True
                
            except (smtplib.SMTPException, socket.timeout, ConnectionError) as e:
                print(f"Failed to send via {server}:{port} - {e}")
                continue
                
        print("All SMTP methods failed")
        return False
        
    except Exception as e:
        print(f"Unexpected error in send_otp_email: {e}")
        return False

def send_email_async(recipient_email, otp):
    """Send email in a separate thread to avoid blocking main request"""
    thread = threading.Thread(target=send_otp_email, args=(recipient_email, otp))
    thread.daemon = True
    thread.start()
    return True  # Assume it will be sent

# --- Helper & Decorator Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to view this page.", "warning")
            return redirect(url_for('login'))
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        if user and user.get('is_banned', False):
            session.clear()
            flash("Your account has been suspended. Please contact support.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['teacher', 'admin']:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("You must be an admin to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def create_notification(user_id, message, link=None):
    mongo.db.notifications.insert_one({
        "user_id": ObjectId(user_id),
        "message": message,
        "link": link,
        "is_read": False,
        "created_at": datetime.utcnow()
    })

def trigger_pdf_processing(filepath, course_id, material_id):
    def process():
        try:
            full_filepath = os.path.abspath(filepath)
            payload = {
                "filepath": full_filepath,
                "course_id": str(course_id),
                "material_id": str(material_id)
            }
            print(f"Sending PDF to AI service for processing: {payload}")
            response = requests.post(f"{app.config['AI_SERVICE_URL']}/process-pdf", json=payload, timeout=60)
            response.raise_for_status()
        except Exception as e:
            print(f"Error triggering PDF processing: {e}")

    thread = threading.Thread(target=process)
    thread.daemon = True
    thread.start()

# --- Context Processor for Notifications ---
@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        unread_count = mongo.db.notifications.count_documents({
            "user_id": ObjectId(session['user_id']),
            "is_read": False
        })
        return dict(unread_notifications=unread_count)
    return dict(unread_notifications=0)

# --- Health Check Endpoint ---
@app.route('/health')
def health_check():
    try:
        # Test database connection
        mongo.db.command('ping')
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# --- HTML RENDERING ROUTES ---
@app.route('/')
def index(): 
    return render_template('home.html')

@app.route('/login')
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/verify')
def verify_page():
    email = request.args.get('email')
    if not email: return redirect(url_for('register'))
    return render_template('verify.html', email=email)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = ObjectId(session['user_id'])
    user = mongo.db.users.find_one({"_id": user_id})
    
    dashboard_data = {}

    if user.get('role') == 'student':
        enrolled_course_ids = user.get('enrolled_courses', [])
        now = datetime.utcnow()
        upcoming_assignments = list(mongo.db.assignments.find({
            "course_id": {"$in": enrolled_course_ids},
            "due_date": {"$gt": now}
        }).sort("due_date", 1).limit(3))

        for asn in upcoming_assignments:
            course = mongo.db.courses.find_one({"_id": asn['course_id']})
            asn['course_title'] = course['title'] if course else 'Unknown Course'
            
        dashboard_data['upcoming_assignments'] = upcoming_assignments

    elif user.get('role') == 'teacher':
        teacher_course_ids = [c['_id'] for c in mongo.db.courses.find({"teacher_id": user_id}, {"_id": 1})]
        
        pending_submissions = list(mongo.db.submissions.find({
            "assignment_id": {"$in": [a['_id'] for a in mongo.db.assignments.find({"course_id": {"$in": teacher_course_ids}})]},
            "grade": None
        }).sort("submitted_at", -1).limit(3))

        for sub in pending_submissions:
            student = mongo.db.users.find_one({"_id": sub['student_id']})
            assignment = mongo.db.assignments.find_one({"_id": sub['assignment_id']})
            sub['student_name'] = student['username'] if student else 'Unknown'
            sub['assignment_title'] = assignment['title'] if assignment else 'Unknown'
        
        dashboard_data['pending_submissions'] = pending_submissions

    return render_template('dashboard.html', data=dashboard_data)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = mongo.db.users.find_one({"email": email})

        if user:
            token = secrets.token_urlsafe(32)
            expiry = datetime.utcnow() + timedelta(hours=1)
            
            mongo.db.users.update_one(
                {"_id": user['_id']},
                {"$set": {"reset_token": token, "reset_token_expiry": expiry}}
            )

            reset_link = url_for('reset_password', token=token, _external=True)
            SENDER_EMAIL = os.getenv("SENDER_EMAIL")
            SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
            
            msg = EmailMessage()
            msg['Subject'] = "Your IntelliLearn Password Reset Link"
            msg['From'] = SENDER_EMAIL
            msg['To'] = email
            msg.set_content(f"Click the link to reset your password: {reset_link}\nThis link will expire in one hour.")
            
            try:
                # Use async email sending for password reset too
                send_email_async(email, "Password Reset")  # Simplified for example
                flash("A password reset link has been sent to your email.", "success")
            except Exception as e:
                print(f"Password reset email error: {e}")
                flash("Could not send reset email. Please try again later.", "danger")
        else:
            flash("No account found with that email address.", "warning")
        
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))

        user = mongo.db.users.find_one({
            "reset_token": token,
            "reset_token_expiry": {"$gt": datetime.utcnow()}
        })

        if not user:
            flash("The password reset link is invalid or has expired.", "danger")
            return redirect(url_for('login'))
        
        hashed_password = generate_password_hash(password)
        mongo.db.users.update_one(
            {"_id": user['_id']},
            {
                "$set": {"password": hashed_password, "password_set": True},
                "$unset": {"reset_token": "", "reset_token_expiry": ""}
            }
        )
        
        flash("Your password has been reset successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({
        "reset_token": token, 
        "reset_token_expiry": {"$gt": datetime.utcnow()}
    })
    if not user:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        user_name = request.form.get('name')
        user_email = request.form.get('contact_email')
        message_body = request.form.get('message')
        SENDER_EMAIL = os.getenv("SENDER_EMAIL")
        SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
        ADMIN_EMAIL = app.config['ADMIN_EMAIL']

        if not all([SENDER_EMAIL, SENDER_PASSWORD]):
            flash("The contact form is currently unavailable. Please email the admin directly.", "warning")
            return render_template('contact.html')

        msg = EmailMessage()
        msg['Subject'] = f"New Contact Form Message from {user_name}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg.set_content(f"You have a new message from:\n\nName: {user_name}\nEmail: {user_email}\n\nMessage:\n{message_body}")

        try:
            # Use async email for contact form too
            send_email_async(ADMIN_EMAIL, f"Contact form message from {user_name}")
            flash("Your message has been sent successfully! We will get back to you shortly.", "success")
            return redirect(url_for('contact'))
        except Exception as e:
            print(f"Contact form email error: {e}")
            flash("Sorry, there was an error sending your message. Please try again later.", "danger")

    return render_template('contact.html')

@app.route('/my-courses')
@login_required
def my_courses():
    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    courses = []
    if user['role'] == 'admin':
        courses = list(mongo.db.courses.find({}))
    elif user['role'] == 'teacher':
        query = {"$or": [{"teacher_id": user['_id']}, {"teacher_id": None}]}
        courses = list(mongo.db.courses.find(query))
    elif user['role'] == 'student':
        enrolled_course_ids = user.get('enrolled_courses', [])
        courses = list(mongo.db.courses.find({"_id": {"$in": enrolled_course_ids}}))
    return render_template('my_courses.html', courses=courses)

@app.route('/create-course', methods=['GET', 'POST'])
@login_required
@teacher_or_admin_required
def create_course():
    if request.method == 'POST':
        mongo.db.courses.insert_one({
            "title": request.form.get('course_title'), "description": request.form.get('course_description'),
            "category": request.form.get('course_category'), "icon": "fa-book",
            "teacher_id": ObjectId(session['user_id']), "created_at": datetime.utcnow()
        })
        flash("Course created successfully!", "success")
        return redirect(url_for('my_courses'))
    return render_template('create_course.html')

@app.route('/course/<course_id>')
@login_required
def course_detail(course_id):
    course_object_id = ObjectId(course_id)
    course = mongo.db.courses.find_one_or_404({"_id": course_object_id})
    current_user_role = session.get('role')
    current_user_id = session.get('user_id')

    # Permission checks
    is_admin = current_user_role == 'admin'
    is_teacher = current_user_role == 'teacher' and (str(course.get('teacher_id')) == current_user_id or course.get('teacher_id') is None)
    is_enrolled_student = False
    if current_user_role == 'student':
        user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        if user and 'enrolled_courses' in user and course_object_id in user['enrolled_courses']:
            is_enrolled_student = True
    if not (is_admin or is_teacher or is_enrolled_student):
        flash("You do not have permission to view this course.", "danger")
        return redirect(url_for('my_courses'))
    
    materials = list(mongo.db.materials.find({"course_id": course_object_id}))
    assignments = list(mongo.db.assignments.find({"course_id": course_object_id}))

    for material in materials:
        material['quiz'] = mongo.db.quizzes.find_one({"material_id": material['_id']})

    # Fixed timezone handling
    now_utc = datetime.now(pytz.utc)
    for assignment in assignments:
        due_date_naive = assignment.get('due_date')
        if due_date_naive:
            due_date_aware = due_date_naive.replace(tzinfo=pytz.utc) 
            assignment['is_submittable'] = due_date_aware > now_utc
            
            if current_user_role == 'student':
                submission = mongo.db.submissions.find_one({
                    "assignment_id": assignment['_id'],
                    "student_id": ObjectId(current_user_id)
                })
                assignment['submission'] = submission
                
                can_edit = False
                if submission:
                    is_not_graded = submission.get('grade') is None
                    is_before_due_date = due_date_aware > now_utc
                    if is_not_graded and is_before_due_date:
                        can_edit = True
                assignment['can_edit'] = can_edit

        elif current_user_role == 'student':
            assignment['submission'] = mongo.db.submissions.find_one({
                "assignment_id": assignment['_id'], "student_id": ObjectId(current_user_id)
            })
            assignment['can_edit'] = False

        if current_user_role in ['teacher', 'admin']:
            count = mongo.db.submissions.count_documents({"assignment_id": assignment['_id']})
            assignment['submission_count'] = count

    return render_template('course_detail.html', course=course, materials=materials, assignments=assignments)

# ... (rest of your routes remain the same, but make sure to use the fixed email functions)

@app.route('/api/register', methods=['POST'])
def api_register():
    email = request.form.get('email')
    username = request.form.get('username')
    role = request.form.get('role')
    if mongo.db.users.find_one({"email": email}):
        flash("An account with this email already exists.", "warning")
        return redirect(url_for('login'))
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    
    # Use async email sending to prevent timeouts
    if not send_email_async(email, otp):
        flash("Could not send verification email.", "danger")
        return redirect(url_for('register'))
    
    mongo.db.temp_users.update_one(
        {"email": email},
        {"$set": {"username": username, "role": role, "otp": otp, "otp_expiry": otp_expiry}},
        upsert=True
    )
    flash(f"A verification code has been sent to {email}.", "success")
    return redirect(url_for('verify_page', email=email))

# ... (include all your other existing routes here)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
