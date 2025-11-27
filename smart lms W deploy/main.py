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
# --- Improved Email Functions with Brevo SMTP ---
# --- Improved Email Functions with Brevo SMTP ---
# --- Improved Email Functions with Resend API ---
import requests
# --- Email Function using Brevo API ---
def send_otp_email(recipient_email, otp):
    BREVO_API_KEY = os.getenv('BREVO_API_KEY')  # Your Brevo API key
    SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'swapnilrao729@gmail.com')
    SENDER_NAME = "IntelliLearn"
    
    print(f"🔧 Using Brevo API for: {recipient_email}")
    
    if not BREVO_API_KEY:
        print("❌ Brevo API key missing. Using fallback.")
        print(f"📧 FALLBACK OTP for {recipient_email}: {otp}")
        return True

    try:
        # Brevo API endpoint
        url = "https://api.brevo.com/v3/smtp/email"
        
        # Email payload for Brevo API
        payload = {
            "sender": {
                "name": SENDER_NAME,
                "email": SENDER_EMAIL
            },
            "to": [
                {
                    "email": recipient_email,
                    "name": recipient_email.split('@')[0]
                }
            ],
            "subject": "Your IntelliLearn Verification Code",
            "htmlContent": f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #2563eb; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; }}
                    .otp-code {{ 
                        font-size: 32px; 
                        font-weight: bold; 
                        color: #2563eb; 
                        text-align: center; 
                        margin: 30px 0;
                        letter-spacing: 5px;
                    }}
                    .footer {{ 
                        margin-top: 30px; 
                        padding-top: 20px; 
                        border-top: 1px solid #e5e7eb;
                        font-size: 14px;
                        color: #6b7280;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>IntelliLearn</h1>
                    </div>
                    <div class="content">
                        <h2>Your Verification Code</h2>
                        <p>Use the following verification code to complete your registration:</p>
                        <div class="otp-code">{otp}</div>
                        <p>This code will expire in <strong>10 minutes</strong>.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>Best regards,<br><strong>The IntelliLearn Team</strong></p>
                        <p><small>This is an automated message, please do not reply to this email.</small></p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
        
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY
        }
        
        print(f"🔄 Sending email via Brevo API to {recipient_email}...")
        
        # Make HTTP request to Brevo API
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 201:
            print(f"✅ Email sent successfully via Brevo API!")
            return True
        else:
            print(f"❌ Brevo API failed with status {response.status_code}: {response.text}")
            
            # Provide specific error guidance
            if response.status_code == 401:
                print("💡 Authentication failed. Please check your Brevo API key.")
            elif response.status_code == 402:
                print("💡 Payment required. Check your Brevo account balance.")
            elif response.status_code == 403:
                print("💡 Access forbidden. Check API key permissions.")
            elif response.status_code == 429:
                print("💡 Rate limit exceeded. Try again later.")
            
            # Fallback to console
            print(f"📧 FALLBACK OTP for {recipient_email}: {otp}")
            return True
            
    except requests.exceptions.Timeout:
        print(f"⏰ Brevo API timeout. Using fallback.")
        print(f"📧 FALLBACK OTP for {recipient_email}: {otp}")
        return True
    except Exception as e:
        print(f"❌ Brevo API error: {str(e)}")
        print(f"📧 FALLBACK OTP for {recipient_email}: {otp}")
        return True
def send_email_async(recipient_email, otp):
    """Send email in a separate thread"""
    def send_wrapper():
        try:
            send_otp_email(recipient_email, otp)
        except Exception as e:
            print(f"Async email error: {e}")
    
    thread = threading.Thread(target=send_wrapper)
    thread.daemon = True
    thread.start()
    return True
# Debug email configuration
# Debug email configuration
# Debug email configuration
print(f"🔧 EMAIL CONFIG DEBUG:")
print(f"   BREVO_API_KEY: {'✅ Set' if os.getenv('BREVO_API_KEY') else '❌ Missing'}")
print(f"   SENDER_EMAIL: ✅ {os.getenv('SENDER_EMAIL', 'swapnilrao729@gmail.com')}")
print(f"   BREVO_USERNAME: {'✅ Set' if os.getenv('BREVO_SMTP_USERNAME') else '❌ Missing'}")
print(f"   BREVO_PASSWORD: {'✅ Set' if os.getenv('BREVO_SMTP_PASSWORD') else '❌ Missing'}")
def send_email_async(recipient_email, otp):
    """Send email in a separate thread to avoid blocking main request"""
    def send_wrapper():
        try:
            send_otp_email(recipient_email, otp)
        except Exception as e:
            print(f"Async email error: {e}")
    
    thread = threading.Thread(target=send_wrapper)
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
            
            # Use async email for password reset
            email_content = f"Click the link to reset your password: {reset_link}\nThis link will expire in one hour."
            send_email_async(email, email_content)
            flash("A password reset link has been sent to your email.", "success")
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
        ADMIN_EMAIL = app.config['ADMIN_EMAIL']

        # Use async email for contact form
        email_content = f"New contact form message from {user_name} ({user_email}):\n\n{message_body}"
        send_email_async(ADMIN_EMAIL, email_content)
        
        flash("Your message has been sent successfully! We will get back to you shortly.", "success")
        return redirect(url_for('contact'))

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

# FIXED: Only one create_course route definition
@app.route('/create-course', methods=['GET', 'POST'])
@login_required
@teacher_or_admin_required
def create_course():
    if request.method == 'POST':
        mongo.db.courses.insert_one({
            "title": request.form.get('course_title'), 
            "description": request.form.get('course_description'),
            "category": request.form.get('course_category'), 
            "icon": "fa-book",
            "teacher_id": ObjectId(session['user_id']), 
            "created_at": datetime.utcnow()
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

@app.route('/course/<course_id>/students')
@login_required
@teacher_or_admin_required
def enrolled_students(course_id):
    course_oid = ObjectId(course_id)
    course = mongo.db.courses.find_one_or_404({"_id": course_oid})

    # Optional: Extra permission check for teachers who aren't admins
    if session['role'] == 'teacher' and str(course.get('teacher_id')) != session['user_id']:
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('course_detail', course_id=course_id))

    # Find all users who are students and are enrolled in this course
    enrolled_users = list(mongo.db.users.find({
        "role": "student",
        "enrolled_courses": course_oid
    }))

    # Get all assignments for this course to calculate totals
    assignments = list(mongo.db.assignments.find({"course_id": course_oid}, {"_id": 1}))
    total_assignments = len(assignments)

    # For each student, count how many assignments they have NOT submitted
    if total_assignments > 0:
        assignment_ids = [a['_id'] for a in assignments]
        for student in enrolled_users:
            submitted_count = mongo.db.submissions.count_documents({
                "student_id": student['_id'],
                "assignment_id": {"$in": assignment_ids}
            })
            student['pending_count'] = total_assignments - submitted_count
    else:
        for student in enrolled_users:
            student['pending_count'] = 0

    return render_template('enrolled_students.html', course=course, students=enrolled_users, total_assignments=total_assignments)

@app.route('/course/<course_id>/student/<student_id>')
@login_required
@teacher_or_admin_required
def student_detail(course_id, student_id):
    course_oid = ObjectId(course_id)
    student_oid = ObjectId(student_id)

    course = mongo.db.courses.find_one_or_404({"_id": course_oid})
    student = mongo.db.users.find_one_or_404({"_id": student_oid, "role": "student"})

    # --- Fetch all data related to this student in this course ---
    assignments = list(mongo.db.assignments.find({"course_id": course_oid}).sort("due_date", 1))
    
    submissions = list(mongo.db.submissions.find({
        "student_id": student_oid,
        "assignment_id": {"$in": [a['_id'] for a in assignments]}
    }))
    
    submission_map = {s['assignment_id']: s for s in submissions}

    for assignment in assignments:
        assignment['submission'] = submission_map.get(assignment['_id'])

    total_materials = mongo.db.materials.count_documents({"course_id": course_oid})
    viewed_materials = mongo.db.material_views.count_documents({"course_id": course_oid, "user_id": student_oid})
    
    stats = {
        "engagement": int((viewed_materials / total_materials * 100) if total_materials > 0 else 0),
        "submitted_count": len(submissions),
        "total_assignments": len(assignments)
    }
    
    return render_template('student_detail.html', course=course, student=student, assignments=assignments, stats=stats, now=datetime)

@app.route('/upload-material/<course_id>', methods=['POST'])
@login_required
@teacher_or_admin_required
def upload_material(course_id):
    course = mongo.db.courses.find_one_or_404({"_id": ObjectId(course_id)})
    is_admin = session.get('role') == 'admin'
    course_teacher_id = str(course.get('teacher_id')) if course.get('teacher_id') else None
    is_course_teacher = course_teacher_id == session['user_id']
    is_unclaimed = course.get('teacher_id') is None
    if not (is_admin or is_course_teacher or is_unclaimed):
        flash("You do not have permission to upload materials to this course.", "danger")
        return redirect(url_for('course_detail', course_id=course_id))
    if is_unclaimed and not is_admin: 
        mongo.db.courses.update_one(
            {"_id": ObjectId(course_id)},
            {"$set": {"teacher_id": ObjectId(session['user_id'])}}
        )
    if 'material_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    file = request.files['material_file']
    title = request.form.get('material_title')
    if file.filename == '' or not title:
        flash('No selected file or title', 'danger')
        return redirect(url_for('course_detail', course_id=course_id))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        material_doc = {
            "title": title, "filename": filename, "filepath": filepath,
            "course_id": ObjectId(course_id), "uploaded_by": ObjectId(session['user_id']),
            "uploaded_at": datetime.utcnow()
        }
        result = mongo.db.materials.insert_one(material_doc)
        trigger_pdf_processing(filepath, course_id, result.inserted_id)
        flash('Material uploaded successfully! It will be available for the AI shortly.', 'success')
    else:
        flash('Invalid file type. Only PDFs are allowed.', 'danger')
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/delete-material/<material_id>', methods=['POST'])
@login_required
@teacher_or_admin_required
def delete_material(material_id):
    material = mongo.db.materials.find_one_or_404({"_id": ObjectId(material_id)})
    course = mongo.db.courses.find_one_or_404({"_id": material['course_id']})
    
    # Permission check
    is_admin = session.get('role') == 'admin'
    is_course_teacher = str(course.get('teacher_id')) == session['user_id']
    if not (is_admin or is_course_teacher):
        return jsonify({"success": False, "message": "Permission denied."}), 403

    try:
        os.remove(material['filepath'])
    except FileNotFoundError:
        print(f"Warning: File not found on disk: {material['filepath']}")
    
    mongo.db.materials.delete_one({"_id": ObjectId(material_id)})
    
    return jsonify({"success": True, "message": "Material deleted successfully."})

@app.route('/submit-assignment/<assignment_id>', methods=['POST'])
@login_required
def submit_assignment(assignment_id):
    assignment = mongo.db.assignments.find_one_or_404({"_id": ObjectId(assignment_id)})
    course = mongo.db.courses.find_one_or_404({"_id": assignment['course_id']})
    
    if 'submission_file' not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))

    file = request.files['submission_file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))

    if file and allowed_file(file.filename):
        filename = secure_filename(f"{session['user_id']}_{file.filename}")
        filepath = os.path.join(app.config['ASSIGNMENT_SUBMISSIONS_FOLDER'], filename)
        file.save(filepath)

        mongo.db.submissions.insert_one({
            "assignment_id": ObjectId(assignment_id),
            "student_id": ObjectId(session['user_id']),
            "filename": filename,
            "filepath": filepath,
            "submitted_at": datetime.utcnow(),
            "grade": None,
            "feedback": None
        })

        if course.get('teacher_id'):
            create_notification(course['teacher_id'], f"New submission for '{assignment['title']}' from {session['username']}.", url_for('view_submissions', assignment_id=assignment_id))
        admin_user = mongo.db.users.find_one({"email": app.config['ADMIN_EMAIL']})
        if admin_user:
            create_notification(admin_user['_id'], f"New submission for '{assignment['title']}' from {session['username']}.", url_for('view_submissions', assignment_id=assignment_id))

        flash("Assignment submitted successfully!", "success")
    else:
        flash("Invalid file type.", "danger")

    return redirect(url_for('course_detail', course_id=assignment['course_id']))

@app.route('/resubmit-assignment/<submission_id>', methods=['POST'])
@login_required
def resubmit_assignment(submission_id):
    submission = mongo.db.submissions.find_one_or_404({
        "_id": ObjectId(submission_id),
        "student_id": ObjectId(session['user_id'])
    })
    
    assignment = mongo.db.assignments.find_one_or_404({"_id": submission['assignment_id']})

    if submission.get('grade') is not None:
        flash("Cannot edit a graded submission.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))

    if assignment.get('due_date') < datetime.utcnow():
        flash("Cannot edit a submission after the due date has passed.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))

    if 'submission_file' not in request.files:
        flash("No file selected for re-submission.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))
    
    file = request.files['submission_file']

    if file.filename == '':
        flash("No file selected for re-submission.", "danger")
        return redirect(url_for('course_detail', course_id=assignment['course_id']))

    if file and allowed_file(file.filename):
        try:
            os.remove(submission['filepath'])
        except FileNotFoundError:
            print(f"Warning: Old submission file not found on disk: {submission['filepath']}")

        filename = secure_filename(f"{session['user_id']}_{file.filename}")
        filepath = os.path.join(app.config['ASSIGNMENT_SUBMISSIONS_FOLDER'], filename)
        file.save(filepath)

        mongo.db.submissions.update_one(
            {"_id": ObjectId(submission_id)},
            {
                "$set": {
                    "filename": filename,
                    "filepath": filepath,
                    "submitted_at": datetime.utcnow()
                }
            }
        )
        flash("Assignment submission updated successfully!", "success")
    else:
        flash("Invalid file type for submission.", "danger")

    return redirect(url_for('course_detail', course_id=assignment['course_id']))

@app.route('/view-submissions/<assignment_id>')
@login_required
@teacher_or_admin_required
def view_submissions(assignment_id):
    assignment = mongo.db.assignments.find_one_or_404({"_id": ObjectId(assignment_id)})
    submissions_cursor = mongo.db.submissions.find({"assignment_id": ObjectId(assignment_id)})
    
    submissions_data = []
    for sub in submissions_cursor:
        student = mongo.db.users.find_one({"_id": sub['student_id']})
        if student:
            sub['student_name'] = student['username']
            submissions_data.append(sub)
            
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions_data)

@app.route('/grade-submission/<submission_id>', methods=['POST'])
@login_required
@teacher_or_admin_required
def grade_submission(submission_id):
    grade = request.form.get('grade')
    feedback = request.form.get('feedback')

    mongo.db.submissions.update_one(
        {"_id": ObjectId(submission_id)},
        {"$set": {"grade": grade, "feedback": feedback}}
    )

    submission = mongo.db.submissions.find_one({"_id": ObjectId(submission_id)})
    assignment = mongo.db.assignments.find_one({"_id": submission['assignment_id']})
    create_notification(submission['student_id'], f"Your submission for '{assignment['title']}' has been graded.", url_for('course_detail', course_id=assignment['course_id']))

    flash("Grade saved successfully!", "success")
    return redirect(url_for('view_submissions', assignment_id=str(submission['assignment_id'])))

@app.route('/uploads/submissions/<filename>')
@login_required
def view_submission_file(filename):
    try:
        return send_from_directory(app.config['ASSIGNMENT_SUBMISSIONS_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/course/<course_id>/create-assignment', methods=['GET', 'POST'])
@login_required
@teacher_or_admin_required
def create_assignment(course_id):
    course = mongo.db.courses.find_one_or_404({"_id": ObjectId(course_id)})
    if request.method == 'POST':
        title = request.form.get('assignment_title')
        description = request.form.get('assignment_description')
        due_date_str = request.form.get('due_date')
        
        IST = pytz.timezone('Asia/Kolkata')
        naive_due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        local_due_date = IST.localize(naive_due_date).replace(hour=23, minute=59, second=59)
        due_date_utc = local_due_date.astimezone(pytz.utc)
        
        assignment_doc = {
            "title": title, "description": description, "due_date": due_date_utc,
            "course_id": ObjectId(course_id), "created_at": datetime.utcnow(),
            "filename": None, "filepath": None
        }
        if 'assignment_file' in request.files:
            file = request.files['assignment_file']
            if file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['ASSIGNMENT_UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    assignment_doc['filename'] = filename
                    assignment_doc['filepath'] = filepath
                else:
                    flash("Invalid file type for assignment attachment.", "danger")
                    return render_template('create_assignment.html', course=course)

        mongo.db.assignments.insert_one(assignment_doc)
        estimated_time = "2 hours (placeholder)"
        enrolled_students = list(mongo.db.users.find({
            "enrolled_courses": ObjectId(course_id), "role": "student"
        }))
        for student in enrolled_students:
            create_notification(
                user_id=student['_id'],
                message=f"New assignment posted for '{course['title']}': {title}. Estimated time: {estimated_time}.",
                link=url_for('course_detail', course_id=course_id)
            )
        flash("Assignment created and students notified!", "success")
        return redirect(url_for('course_detail', course_id=course_id))

    return render_template('create_assignment.html', course=course)

@app.route('/uploads/assignments/<filename>')
@login_required
def view_assignment_file(filename):
    try:
        return send_from_directory(app.config['ASSIGNMENT_UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/browse-courses')
@login_required
def browse_courses():
    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    enrolled_course_ids = user.get('enrolled_courses', [])
    pending_requests = list(mongo.db.enrollment_requests.find(
        {"student_id": user['_id'], "status": "pending"},
        {"course_id": 1}
    ))
    pending_course_ids = [req['course_id'] for req in pending_requests]
    exclude_ids = enrolled_course_ids + pending_course_ids
    available_courses = list(mongo.db.courses.find({"_id": {"$nin": exclude_ids}}))
    return render_template('browse_courses.html', courses=available_courses)

@app.route('/request-enrollment/<course_id>', methods=['POST'])
@login_required
def request_enrollment(course_id):
    course = mongo.db.courses.find_one_or_404({"_id": ObjectId(course_id)})
    student_id = ObjectId(session['user_id'])
    student_name = session['username']
    mongo.db.enrollment_requests.insert_one({
        "student_id": student_id, "course_id": ObjectId(course_id),
        "teacher_id": course.get('teacher_id'), "status": "pending",
        "requested_at": datetime.utcnow()
    })
    if course.get('teacher_id'):
        create_notification(
            user_id=course['teacher_id'],
            message=f"New enrollment request from {student_name} for '{course['title']}'.",
            link=url_for('manage_requests')
        )
    admin_user = mongo.db.users.find_one({"email": app.config['ADMIN_EMAIL']})
    if admin_user:
        create_notification(
            user_id=admin_user['_id'],
            message=f"New enrollment request from {student_name} for '{course['title']}'.",
            link=url_for('manage_requests')
        )
    flash("Your request to enroll has been sent for approval.", "success")
    return redirect(url_for('browse_courses'))

@app.route('/material/<material_id>/create-quiz', methods=['GET', 'POST'])
@login_required
@teacher_or_admin_required
def create_quiz(material_id):
    material = mongo.db.materials.find_one_or_404({"_id": ObjectId(material_id)})
    if request.method == 'POST':
        quiz_title = request.form.get('quiz_title')
        quiz_id = mongo.db.quizzes.insert_one({
            'title': quiz_title,
            'material_id': ObjectId(material_id),
            'course_id': material['course_id'],
            'created_by': ObjectId(session['user_id']),
            'type': 'manual',
            'created_at': datetime.utcnow()
        }).inserted_id

        questions = []
        for key, value in request.form.items():
            if key.startswith('question_text_'):
                index = key.split('_')[-1]
                question_text = value
                options = request.form.getlist(f'option_{index}')
                correct_answer = int(request.form.get(f'correct_answer_{index}'))
                
                questions.append({
                    'quiz_id': quiz_id,
                    'text': question_text,
                    'options': options,
                    'correct_option': correct_answer
                })
        
        if questions:
            mongo.db.questions.insert_many(questions)

        flash('Quiz created successfully!', 'success')
        return redirect(url_for('course_detail', course_id=material['course_id']))

    return render_template('create_quiz.html', material=material)

@app.route('/quiz/<quiz_id>/take')
@login_required
def take_quiz(quiz_id):
    quiz = mongo.db.quizzes.find_one_or_404({"_id": ObjectId(quiz_id)})
    questions = list(mongo.db.questions.find({'quiz_id': quiz['_id']}))
    return render_template('take_quiz.html', quiz=quiz, questions=questions)

@app.route('/api/quiz/<quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz_oid = ObjectId(quiz_id)
    answers = request.get_json().get('answers')
    
    questions = list(mongo.db.questions.find({'quiz_id': quiz_oid}))
    
    score = 0
    results = []
    for question in questions:
        question_id = str(question['_id'])
        user_answer_index = answers.get(question_id)
        is_correct = False
        if user_answer_index is not None and int(user_answer_index) == question['correct_option']:
            score += 1
            is_correct = True
        
        results.append({
            'question_id': question_id,
            'is_correct': is_correct,
            'user_answer': int(user_answer_index) if user_answer_index is not None else None,
            'correct_answer': question['correct_option']
        })

    attempt_id = mongo.db.quiz_attempts.insert_one({
        'user_id': ObjectId(session['user_id']),
        'quiz_id': quiz_oid,
        'score': score,
        'total_questions': len(questions),
        'results': results,
        'submitted_at': datetime.utcnow()
    }).inserted_id

    return jsonify({'success': True, 'redirect_url': url_for('quiz_results', attempt_id=attempt_id)})

@app.route('/quiz/results/<attempt_id>')
@login_required
def quiz_results(attempt_id):
    attempt = mongo.db.quiz_attempts.find_one_or_404({"_id": ObjectId(attempt_id)})
    quiz = mongo.db.quizzes.find_one_or_404({"_id": attempt['quiz_id']})
    questions = list(mongo.db.questions.find({'quiz_id': attempt['quiz_id']}))
    
    for result in attempt['results']:
        for q in questions:
            if str(q['_id']) == result['question_id']:
                result['question_text'] = q['text']
                result['options'] = q['options']
                break
                
    return render_template('quiz_results.html', attempt=attempt, quiz=quiz)

@app.route('/manage-requests')
@login_required
@teacher_or_admin_required
def manage_requests():
    query = {}
    if session['role'] == 'teacher':
        query = {"teacher_id": ObjectId(session['user_id']), "status": "pending"}
    elif session['role'] == 'admin':
        query = {"status": "pending"}
    requests_cursor = mongo.db.enrollment_requests.find(query)
    requests_data = []
    for req in requests_cursor:
        student = mongo.db.users.find_one({"_id": req['student_id']})
        course = mongo.db.courses.find_one({"_id": req['course_id']})
        if student and course:
            req['student_name'] = student['username']
            req['course_title'] = course['title']
            requests_data.append(req)
    return render_template('manage_requests.html', requests=requests_data)

@app.route('/handle-request/<request_id>/<action>', methods=['POST'])
@login_required
@teacher_or_admin_required
def handle_request(request_id, action):
    request_doc = mongo.db.enrollment_requests.find_one_or_404({"_id": ObjectId(request_id)})
    student_id = request_doc['student_id']
    course = mongo.db.courses.find_one({"_id": request_doc['course_id']})
    if action == 'approve':
        mongo.db.users.update_one(
            {"_id": student_id},
            {"$addToSet": {"enrolled_courses": request_doc['course_id']}}
        )
        mongo.db.enrollment_requests.update_one(
            {"_id": ObjectId(request_id)}, {"$set": {"status": "approved"}}
        )
        create_notification(
            user_id=student_id,
            message=f"Your request to enroll in '{course['title']}' has been approved!",
            link=url_for('course_detail', course_id=course['_id'])
        )
        flash("Enrollment request approved.", "success")
    elif action == 'reject':
        mongo.db.enrollment_requests.update_one(
            {"_id": ObjectId(request_id)}, {"$set": {"status": "rejected"}}
        )
        create_notification(
            user_id=student_id,
            message=f"Your request to enroll in '{course['title']}' has been rejected."
        )
        flash("Enrollment request rejected.", "warning")
    return redirect(url_for('manage_requests'))

@app.route('/uploads/pdfs/<filename>')
@login_required
def view_pdf(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/manage-users')
@login_required
@admin_required
def admin_manage_users():
    users = list(mongo.db.users.find({}))
    return render_template('admin_manage_users.html', users=users)

@app.route('/admin/manage-courses')
@login_required
@admin_required
def admin_manage_courses():
    courses = list(mongo.db.courses.find({}))
    return render_template('admin_manage_courses.html', courses=courses)

@app.route('/admin/delete-course/<course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    course_object_id = ObjectId(course_id)
    materials_to_delete = list(mongo.db.materials.find({"course_id": course_object_id}))
    for material in materials_to_delete:
        try:
            os.remove(material['filepath'])
        except FileNotFoundError:
            print(f"Warning: File not found for deletion: {material['filepath']}")
    mongo.db.materials.delete_many({"course_id": course_object_id})
    mongo.db.enrollment_requests.delete_many({"course_id": course_object_id})
    mongo.db.courses.delete_one({"_id": course_object_id})
    flash("Course and all associated materials have been permanently deleted.", "success")
    return redirect(url_for('admin_manage_courses'))

@app.route('/admin/change-role/<user_id>', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    user_to_update = mongo.db.users.find_one_or_404({"_id": ObjectId(user_id)})
    if user_to_update['email'] == app.config['ADMIN_EMAIL']:
        return jsonify({"success": False, "message": "Cannot change admin role."}), 403

    new_role = request.json.get('new_role')
    if new_role not in ['student', 'teacher']:
        return jsonify({"success": False, "message": "Invalid role."}), 400
        
    mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role}}
    )
    return jsonify({"success": True, "message": f"Role updated to {new_role}."})

@app.route('/admin/delete-user/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = mongo.db.users.find_one_or_404({"_id": ObjectId(user_id)})
    if user_to_delete['email'] == app.config['ADMIN_EMAIL']:
        flash("Cannot delete the primary admin account.", "danger")
        return redirect(url_for('admin_manage_users'))
    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    flash(f"User {user_to_delete['username']} has been deleted.", "success")
    return redirect(url_for('admin_manage_users'))

@app.route('/admin/toggle-ban/<user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_ban_user(user_id):
    user_to_update = mongo.db.users.find_one_or_404({"_id": ObjectId(user_id)})
    if user_to_update['email'] == app.config['ADMIN_EMAIL']:
        return jsonify({"success": False, "message": "Cannot ban admin."}), 403

    new_ban_status = not user_to_update.get('is_banned', False)
    mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_banned": new_ban_status}}
    )
    action = "banned" if new_ban_status else "unbanned"
    return jsonify({"success": True, "message": f"User has been {action}.", "is_banned": new_ban_status})

@app.route('/performance')
@login_required
def performance():
    user_id = ObjectId(session['user_id'])
    user = mongo.db.users.find_one({"_id": user_id})

    if user['role'] == 'student':
        enrolled_courses_ids = user.get('enrolled_courses', [])
        courses_data = []
        for course_id in enrolled_courses_ids:
            course = mongo.db.courses.find_one({"_id": course_id})
            if course:
                total_materials = mongo.db.materials.count_documents({"course_id": course_id})
                
                viewed_materials_count = mongo.db.material_views.count_documents({
                    "user_id": user_id,
                    "course_id": course_id
                })

                completion = (viewed_materials_count / total_materials * 100) if total_materials > 0 else 0
                
                courses_data.append({
                    "title": course['title'],
                    "completion": int(completion)
                })
        return render_template('student_performance.html', courses_data=courses_data)

    elif user['role'] in ['teacher', 'admin']:
        teacher_id = user['_id'] if user['role'] == 'teacher' else None
        query = {}
        if teacher_id:
            query = {"uploaded_by": teacher_id}
        uploaded_materials = list(mongo.db.materials.find(query).sort("uploaded_at", -1))
        for material in uploaded_materials:
            course = mongo.db.courses.find_one({"_id": material['course_id']})
            material['course_title'] = course['title'] if course else 'Unknown Course'
        return render_template('teacher_uploads.html', materials=uploaded_materials)

    return redirect(url_for('dashboard'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        new_username = request.form.get('username')
        if new_username != session['username']:
            mongo.db.users.update_one(
                {"_id": ObjectId(session['user_id'])},
                {"$set": {"username": new_username}}
            )
            session['username'] = new_username
            flash("Username updated successfully!", "success")
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(f"{session['user_id']}_{file.filename}")
                    filepath = os.path.join(app.config['AVATAR_UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    avatar_url = f"uploads/avatars/{filename}"
                    mongo.db.users.update_one(
                        {"_id": ObjectId(session['user_id'])},
                        {"$set": {"avatar": url_for('static', filename=avatar_url)}}
                    )
                    session['user_avatar'] = url_for('static', filename=avatar_url)
                    flash("Profile picture updated successfully!", "success")
        return redirect(url_for('settings'))
    return render_template('settings.html')

@app.route('/summarize/<material_id>')
@login_required
def summarize(material_id):
    material = mongo.db.materials.find_one_or_404({"_id": ObjectId(material_id)})
    
    summary_text = ""
    error_message = None
    response = None

    try:
        doc = fitz.open(material['filepath'])
        full_text = "".join(page.get_text() for page in doc)
        doc.close()

        if not full_text.strip():
            summary_text = "This PDF appears to be empty or contains no readable text."
        else:
            payload = {"text": full_text}
            response = requests.post(
                f"{app.config['AI_SERVICE_URL']}/summarize-long", 
                json=payload, 
                timeout=180
            ) 
            response.raise_for_status() 
            
            summary_data = response.json()
            if 'summary' in summary_data:
                summary_text = summary_data['summary']
            else:
                error_message = summary_data.get('error', 'An unknown error occurred at the AI service.')

    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.ConnectionError):
            error_message = "Could not connect to the AI summarization service. **It is offline.** Please ensure ai_app.py is running on port 5001."
        else:
            error_message = f"AI Service communication error. Check the ai_app.py terminal for a traceback. Error: {e}"
    except Exception as e:
        print(f"Error during summarization process: {e}")
        error_message = "An unexpected error occurred while trying to generate the summary."

    return render_template('summary.html', material=material, summary=summary_text, error=error_message)

@app.route('/quiz/<material_id>')
@login_required
def quiz(material_id):
    material = mongo.db.materials.find_one_or_404({"_id": ObjectId(material_id)})
    return render_template('quiz.html', material=material)

@app.route('/messages')
@app.route('/messages/<conversation_id>')
@login_required
def messages(conversation_id=None):
    user_id = ObjectId(session['user_id'])
    IST = pytz.timezone('Asia/Kolkata')

    conversations_cursor = mongo.db.conversations.find({
        "participants": user_id
    }).sort("last_updated", -1)

    conversations_data = []
    for convo in conversations_cursor:
        other_participant_id = next((p for p in convo['participants'] if p != user_id), None)
        if other_participant_id:
            other_user = mongo.db.users.find_one({"_id": other_participant_id})
            if other_user:
                convo['other_user'] = other_user
                last_message = mongo.db.messages.find_one(
                    {"conversation_id": convo['_id']},
                    sort=[("timestamp", -1)]
                )
                convo['last_message'] = last_message
                conversations_data.append(convo)

    active_conversation = None
    active_messages = []
    
    if not conversation_id and conversations_data:
        conversation_id = str(conversations_data[0]['_id'])

    if conversation_id:
        active_conversation = mongo.db.conversations.find_one({"_id": ObjectId(conversation_id), "participants": user_id})
        if active_conversation:
            other_user_id = next((p for p in active_conversation['participants'] if p != user_id), None)
            other_user = mongo.db.users.find_one({"_id": other_user_id})
            if other_user:
                active_conversation['other_user'] = other_user
                messages_cursor = mongo.db.messages.find({"conversation_id": active_conversation['_id']}).sort("timestamp", 1)
                for msg in messages_cursor:
                    utc_time = msg['timestamp'].replace(tzinfo=pytz.utc)
                    ist_time = utc_time.astimezone(IST)
                    msg['formatted_timestamp'] = ist_time.strftime('%I:%M %p')
                    active_messages.append(msg)
            else:
                active_conversation = None 
    
    return render_template('messages.html', conversations=conversations_data, active_conversation=active_conversation, messages=active_messages)

@app.route('/messages/new', methods=['GET', 'POST'])
@login_required
def new_message():
    if request.method == 'POST':
        recipient_id = ObjectId(request.form.get('recipient_id'))
        message_body = request.form.get('message_body')
        sender_id = ObjectId(session['user_id'])
        if sender_id == recipient_id:
            flash("You cannot send a message to yourself.", "warning")
            return redirect(url_for('new_message'))
        conversation = mongo.db.conversations.find_one({
            "participants": {"$all": [sender_id, recipient_id]}
        })
        if not conversation:
            conversation_id = mongo.db.conversations.insert_one({
                "participants": [sender_id, recipient_id],
                "created_at": datetime.utcnow(),
                "last_updated": datetime.utcnow()
            }).inserted_id
        else:
            conversation_id = conversation['_id']
            mongo.db.conversations.update_one(
                {"_id": conversation_id},
                {"$set": {"last_updated": datetime.utcnow()}}
            )
        mongo.db.messages.insert_one({
            "conversation_id": conversation_id,
            "sender_id": sender_id,
            "body": message_body,
            "timestamp": datetime.utcnow()
        })
        create_notification(
            user_id=recipient_id,
            message=f"You have a new message from {session['username']}.",
            link=url_for('messages', conversation_id=str(conversation_id))
        )
        return redirect(url_for('messages', conversation_id=str(conversation_id)))
    users = list(mongo.db.users.find({"_id": {"$ne": ObjectId(session['user_id'])}}))
    return render_template('new_message.html', users=users)

@app.route('/notifications')
@login_required
def notifications():
    user_id = ObjectId(session['user_id'])
    user_notifications = list(mongo.db.notifications.find({"user_id": user_id}).sort("created_at", -1))
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/notifications/mark-as-read', methods=['POST'])
@login_required
def mark_notifications_as_read():
    mongo.db.notifications.update_many(
        {"user_id": ObjectId(session['user_id']), "is_read": False},
        {"$set": {"is_read": True}}
    )
    return jsonify({"success": True})

# --- API & AUTHENTICATION ROUTES ---
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
    send_email_async(email, otp)
    
    mongo.db.temp_users.update_one(
        {"email": email},
        {"$set": {"username": username, "role": role, "otp": otp, "otp_expiry": otp_expiry}},
        upsert=True
    )
    flash(f"A verification code has been sent to {email}.", "success")
    return redirect(url_for('verify_page', email=email))

@app.route('/api/resend-otp', methods=['POST'])
def api_resend_otp():
    email = request.json.get('email')
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)

    user = mongo.db.users.find_one({"email": email})
    if user:
        mongo.db.users.update_one({"email": email}, {"$set": {"otp": otp, "otp_expiry": otp_expiry}})
        send_email_async(email, otp)
        return jsonify({"success": True, "message": "New login code sent."})

    temp_user = mongo.db.temp_users.find_one({"email": email})
    if temp_user:
        mongo.db.temp_users.update_one({"email": email}, {"$set": {"otp": otp, "otp_expiry": otp_expiry}})
        send_email_async(email, otp)
        return jsonify({"success": True, "message": "New verification code sent."})
    
    return jsonify({"success": False, "message": "No account found for this email."}), 404

@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    email = request.form.get('email')
    otp_entered = request.form.get('otp')
    temp_user = mongo.db.temp_users.find_one({"email": email, "otp": otp_entered})
    if temp_user:
        if datetime.utcnow() > temp_user['otp_expiry']:
            flash("Your verification code has expired.", "danger")
            return redirect(url_for('register'))
        user_role = 'admin' if temp_user['email'] == app.config['ADMIN_EMAIL'] else temp_user['role']
        user_id = mongo.db.users.insert_one({
            "username": temp_user['username'], "email": temp_user['email'],
            "role": user_role, "created_at": datetime.utcnow(),
            "enrolled_courses": []
        }).inserted_id
        mongo.db.temp_users.delete_one({"email": email})
        session['user_email'] = email
        session['username'] = temp_user['username']
        session['role'] = user_role
        session['user_id'] = str(user_id)
        session['user_avatar'] = url_for('static', filename='assets/default_avatar.png')
        flash("Account created successfully! You are now logged in.", "success")
        
        newly_created_user = mongo.db.users.find_one({"_id": user_id})
        if not newly_created_user.get('password_set'):
            return redirect(url_for('set_password'))
        else:
            return redirect(url_for('dashboard'))

    user = mongo.db.users.find_one({"email": email, "otp": otp_entered})
    if user:
        if datetime.utcnow() > user['otp_expiry']:
            flash("Your login code has expired.", "danger")
            return redirect(url_for('login'))
        
        user_role = 'admin' if user['email'] == app.config['ADMIN_EMAIL'] else user['role']
        
        session['user_email'] = email
        session['username'] = user['username']
        session['role'] = user_role
        session['user_id'] = str(user['_id'])
        session['user_avatar'] = user.get('avatar', url_for('static', filename='assets/default_avatar.png'))
        flash("Logged in successfully!", "success")

        if not user.get('password_set'):
            return redirect(url_for('set_password'))
        else:
            return redirect(url_for('dashboard'))
            
    flash("Invalid verification code.", "danger")
    return redirect(url_for('verify_page', email=email))

@app.route('/set-password', methods=['GET', 'POST'])
@login_required
def set_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('set_password'))

        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {"password": hashed_password, "password_set": True}}
        )
        flash("Password set successfully! You can now log in with your password.", "success")
        return redirect(url_for('dashboard'))
    return render_template('set_password.html')

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})

    if not check_password_hash(user.get('password', ''), current_password):
        flash("Incorrect current password.", "danger")
        return redirect(url_for('settings'))

    hashed_password = generate_password_hash(new_password)
    mongo.db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"password": hashed_password}}
    )
    flash("Password changed successfully.", "success")
    return redirect(url_for('settings'))

@app.route('/admin/reset-password/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password_set": False, "password": None}}
    )
    flash("User's password has been reset. They will be prompted to set a new one on their next OTP login.", "success")
    return redirect(url_for('admin_manage_users'))

@app.route('/delete-assignment/<assignment_id>', methods=['POST'])
@login_required
@admin_required
def delete_assignment(assignment_id):
    assignment = mongo.db.assignments.find_one_or_404({"_id": ObjectId(assignment_id)})
    course_id = assignment['course_id']

    if assignment.get('filepath'):
        try:
            os.remove(assignment['filepath'])
        except FileNotFoundError:
            print(f"Warning: Assignment file not found on disk: {assignment['filepath']}")
    
    mongo.db.assignments.delete_one({"_id": ObjectId(assignment_id)})
    flash("Assignment deleted successfully.", "success")
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/api/login', methods=['POST'])
def api_login():
    email = request.form.get('email')
    login_method = request.form.get('login_method')
    user = mongo.db.users.find_one({"email": email})

    if not user:
        flash("No account found with this email. Please register first.", "warning")
        return redirect(url_for('register'))

    if login_method == 'password':
        password = request.form.get('password')
        if not user.get('password') or not check_password_hash(user['password'], password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))
        
        user_role = 'admin' if user['email'] == app.config['ADMIN_EMAIL'] else user['role']
        
        session['user_email'] = user['email']
        session['username'] = user['username']
        session['role'] = user_role
        session['user_id'] = str(user['_id'])
        session['user_avatar'] = user.get('avatar', url_for('static', filename='assets/default_avatar.png'))
        flash("Logged in successfully!", "success")
        return redirect(url_for('dashboard'))

    else: # OTP Login
        otp = str(random.randint(100000, 999999))
        otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        send_email_async(email, otp)
        mongo.db.users.update_one({"email": email}, {"$set": {"otp": otp, "otp_expiry": otp_expiry}})
        flash(f"A login code has been sent to {email}.", "success")
        return redirect(url_for('verify_page', email=email))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/api/gemini-chat', methods=['POST'])
@login_required
def gemini_chat():
    try:
        if not GEMINI_API_KEY:
            return jsonify({"error": "AI service is not configured."}), 500
        
        data = request.get_json()
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({"error": "No prompt provided."}), 400
            
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        
        if response.text:
            return jsonify({"response": response.text})
        else:
            return jsonify({"response": "I'm sorry, I couldn't generate a response for that."})

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "An error occurred while communicating with the AI."}), 500

@app.route('/api/generate-ai-quiz', methods=['POST'])
@login_required
def api_generate_ai_quiz():
    data = request.get_json()
    material_id = data.get('material_id')
    
    if not material_id:
        return jsonify({"error": "Missing material ID."}), 400

    response = None 
    
    try:
        material = mongo.db.materials.find_one_or_404({"_id": ObjectId(material_id)})
        
        doc = fitz.open(material['filepath'])
        full_text = "".join(page.get_text() for page in doc)
        doc.close()

        if not full_text.strip():
            return jsonify({"error": "The material contains no readable text for quiz generation."}), 400

        payload = {"text": full_text, "num_questions": 5} 
        
        response = requests.post(f"{app.config['AI_SERVICE_URL']}/generate-quiz", json=payload, timeout=90)
        response.raise_for_status() 
        
        quiz_data = response.json()
        
        return jsonify({"success": True, "questions": quiz_data.get('questions', [])})

    except requests.exceptions.RequestException as e:
        print(f"Error contacting AI service for quiz: {e}")
        if response is not None and response.status_code == 500:
             print(f"AI Service Error: {response.text}")
        return jsonify({"error": "Could not connect to the AI quiz generation service. Check if it's running on port 5001."}), 500
    except Exception as e:
        print(f"Error during AI quiz generation process: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/api/course-chat', methods=['POST'])
@login_required
def course_chat():
    data = request.get_json()
    prompt = data.get('prompt')
    course_id = data.get('course_id')
    if not all([prompt, course_id]):
        return jsonify({"error": "Missing prompt or course_id"}), 400
    try:
        payload = {"question": prompt, "course_id": course_id}
        response = requests.post(f"{app.config['AI_SERVICE_URL']}/ask-course-question", json=payload)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error contacting AI service: {e}")
        return jsonify({"error": "Could not connect to the AI service."}), 500

@app.route('/api/log-material-view', methods=['POST'])
@login_required
def log_material_view():
    data = request.get_json()
    material_id = data.get('material_id')

    if not material_id:
        return jsonify({"success": False, "message": "Material ID is missing."}), 400

    user_id = ObjectId(session['user_id'])
    material_oid = ObjectId(material_id)

    material = mongo.db.materials.find_one({"_id": material_oid})
    if not material:
        return jsonify({"success": False, "message": "Material not found."}), 404

    course_id = material['course_id']
    
    mongo.db.material_views.update_one(
        {"user_id": user_id, "material_id": material_oid},
        {"$set": {
            "course_id": course_id,
            "viewed_at": datetime.utcnow()
        }},
        upsert=True
    )

    return jsonify({"success": True})

@app.route('/api/messages/<conversation_id>/send', methods=['POST'])
@login_required
def send_api_message(conversation_id):
    user_id = ObjectId(session['user_id'])
    convo_id_obj = ObjectId(conversation_id)
    IST = pytz.timezone('Asia/Kolkata')
    conversation = mongo.db.conversations.find_one({"_id": convo_id_obj, "participants": user_id})
    if not conversation:
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json()
    message_body = data.get('body')
    if not message_body:
        return jsonify({"error": "Message body is required"}), 400
    timestamp_utc = datetime.utcnow()
    message_doc = {
        "conversation_id": convo_id_obj,
        "sender_id": user_id,
        "body": message_body,
        "timestamp": timestamp_utc
    }
    mongo.db.messages.insert_one(message_doc)
    mongo.db.conversations.update_one(
        {"_id": convo_id_obj},
        {"$set": {"last_updated": timestamp_utc}}
    )
    recipient_id = next((p for p in conversation['participants'] if p != user_id), None)
    if recipient_id:
        create_notification(
            user_id=recipient_id,
            message=f"You have a new message from {session['username']}.",
            link=url_for('messages', conversation_id=conversation_id)
        )
    ist_time = timestamp_utc.replace(tzinfo=pytz.utc).astimezone(IST)
    message_doc['_id'] = str(message_doc['_id'])
    message_doc['sender_id'] = str(message_doc['sender_id'])
    message_doc['conversation_id'] = str(message_doc['conversation_id'])
    message_doc['formatted_timestamp'] = ist_time.strftime('%I:%M %p')
    del message_doc['timestamp']
    return jsonify({"success": True, "message": message_doc})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False)







