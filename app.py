import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import fitz # PyMuPDF

# --- Flask App Configuration ---
app = Flask(__name__)
# FIX: Set a hardcoded secret key for local development.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'your-super-secret-key-goes-here'

# Use a local SQLite database if the DATABASE_URL environment variable is not set.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# IMPORTANT: These local paths are for demonstration. In production, use cloud storage.
app.config['UPLOAD_FOLDER_STUDENT'] = 'uploads/student_submissions/'
app.config['UPLOAD_FOLDER_TEACHER'] = 'uploads/correct_answers/'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='student')
    assignments_created = db.relationship('Assignment', backref='creator', lazy=True)
    submissions = db.relationship('Submission', backref='student', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    correct_answer_path = db.Column(db.String(255), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submissions = db.relationship('Submission', backref='assignment', lazy=True)

    def __repr__(self):
        return f'<Assignment {self.title}>'

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    submission_path = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Float, nullable=True)
    grade = db.Column(db.String(50), nullable=True)
    numerical_score = db.Column(db.Integer, nullable=True)
    evaluated_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Submission {self.id} by {self.student_id} for {self.assignment_id}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Utility Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page_num in range(doc.page_count):
            page = doc.load_page(page_num)
            text += page.get_text()
        doc.close()
    except Exception as e:
        print(f"Error extracting text from PDF '{pdf_path}': {e}")
    return text

def calculate_similarity_score(student_answer, correct_answer):
    # NOTE: You will need to implement your AI model here.
    # It might be an external service or a smaller, hosted model.
    # This is a placeholder for demonstration purposes.
    return 0.5

def assign_grade(similarity_score):
    if similarity_score >= 0.8:
        return "Excellent (A)", 5
    elif similarity_score >= 0.6:
        return "Good (B)", 4
    elif similarity_score >= 0.4:
        return "Average (C)", 3
    else:
        return "Needs Improvement (D/F)", 1

# --- Flask Routes ---
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('dashboard.html', users=users, user_role='admin')
    elif current_user.role == 'teacher':
        assignments = Assignment.query.filter_by(teacher_id=current_user.id).all()
        all_submissions = Submission.query.join(Assignment).filter(Assignment.teacher_id == current_user.id).all()
        return render_template('dashboard.html', assignments=assignments, all_submissions=all_submissions, user_role='teacher')
    elif current_user.role == 'student':
        submitted_assignment_ids = [s.assignment_id for s in current_user.submissions]
        available_assignments = Assignment.query.filter(Assignment.id.notin_(submitted_assignment_ids)).all()
        my_submissions = Submission.query.filter_by(student_id=current_user.id).all()
        return render_template('dashboard.html', available_assignments=available_assignments, my_submissions=my_submissions, user_role='student')
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    if User.query.filter_by(username=username).first():
        flash('Username already exists. Please choose a different one.', 'danger')
    elif User.query.filter_by(email=email).first():
        flash('Email already registered. Please use a different one.', 'danger')
    else:
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Account for {username} created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('dashboard'))
    Submission.query.filter_by(student_id=user_to_delete.id).delete()
    Assignment.query.filter_by(teacher_id=user_to_delete.id).delete()
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'User {user_to_delete.username} has been deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))
    user_to_update = User.query.get_or_404(user_id)
    new_role = request.form.get('new_role')
    if new_role not in ['student', 'teacher', 'admin']:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('dashboard'))
    user_to_update.role = new_role
    db.session.commit()
    flash(f'Role for {user_to_update.username} changed to {new_role}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/teacher/create_assignment', methods=['POST'])
@login_required
def create_assignment():
    if current_user.role != 'teacher':
        flash('Access denied. Teachers only.', 'danger')
        return redirect(url_for('login'))
    if 'correct_answer_file' not in request.files:
        flash('No file part for correct answers', 'danger')
        return redirect(url_for('dashboard'))
    file = request.files['correct_answer_file']
    if file.filename == '':
        flash('No selected file for correct answers', 'danger')
        return redirect(url_for('dashboard'))
    if file and allowed_file(file.filename):
        # NOTE: This part needs to be replaced with cloud storage upload logic.
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER_TEACHER'], filename)
        file.save(filepath)
        title = request.form.get('title')
        description = request.form.get('description')
        if not title:
            flash('Assignment title is required.', 'danger')
            return redirect(url_for('dashboard'))
        new_assignment = Assignment(
            title=title,
            description=description,
            correct_answer_path=filepath,
            teacher_id=current_user.id
        )
        db.session.add(new_assignment)
        db.session.commit()
        flash('Assignment created successfully!', 'success')
    else:
        flash('Invalid file type for correct answer. Only PDF allowed.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/teacher/evaluate_submission/<int:submission_id>')
@login_required
def teacher_evaluate_submission(submission_id):
    if current_user.role != 'teacher':
        flash('Access denied. Teachers only.', 'danger')
        return redirect(url_for('login'))
    submission = Submission.query.get_or_404(submission_id)
    assignment = Assignment.query.get_or_404(submission.assignment_id)
    if assignment.teacher_id != current_user.id:
        flash('You are not authorized to evaluate this submission.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        # NOTE: You need to download the PDFs from cloud storage here.
        student_answer_text = extract_text_from_pdf(submission.submission_path)
        correct_answer_text = extract_text_from_pdf(assignment.correct_answer_path)
        if not student_answer_text or not correct_answer_text:
            flash("Could not extract text from PDFs. Score set to 0.", 'danger')
            submission.score = 0.0
            submission.grade, submission.numerical_score = assign_grade(0.0)
            db.session.commit()
            return redirect(url_for('dashboard'))
        score = calculate_similarity_score(student_answer_text, correct_answer_text)
        grade, numerical_score = assign_grade(score)
        submission.score = round(score, 4)
        submission.grade = grade
        submission.numerical_score = numerical_score
        db.session.commit()
        flash(f'Submission {submission.id} evaluated successfully!', 'success')
    except Exception as e:
        flash(f"Error during evaluation: {e}.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/student/upload_assignment/<int:assignment_id>', methods=['POST'])
@login_required
def upload_assignment(assignment_id):
    if current_user.role != 'student':
        flash('Access denied. Students only.', 'danger')
        return redirect(url_for('login'))
    assignment = Assignment.query.get_or_404(assignment_id)
    existing_submission = Submission.query.filter_by(
        student_id=current_user.id,
        assignment_id=assignment.id
    ).first()
    if existing_submission:
        flash('You have already submitted for this assignment.', 'warning')
        return redirect(url_for('dashboard'))
    if 'assignment_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    file = request.files['assignment_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
    if file and allowed_file(file.filename):
        # NOTE: This part needs to be replaced with cloud storage upload logic.
        filename = secure_filename(f"{current_user.username}_{assignment.id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER_STUDENT'], filename)
        file.save(filepath)
        new_submission = Submission(
            student_id=current_user.id,
            assignment_id=assignment.id,
            submission_path=filepath
        )
        db.session.add(new_submission)
        db.session.commit()
        flash('Assignment uploaded successfully! Teacher can now evaluate.', 'success')
    else:
        flash('Invalid file type. Only PDF allowed.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/view_submission_results/<int:submission_id>')
@login_required
def view_submission_results(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if not (current_user.id == submission.student_id or (current_user.role == 'teacher' and submission.assignment.teacher_id == current_user.id)):
        flash('Access denied. You can only view your own submissions or submissions to your assignments.', 'danger')
        return redirect(url_for('login'))
    # NOTE: You need to download the PDFs from cloud storage here.
    student_ans_text = extract_text_from_pdf(submission.submission_path)
    correct_ans_text = extract_text_from_pdf(submission.assignment.correct_answer_path)
    evaluated_results = [{
        "question": submission.assignment.title,
        "student_excerpt": student_ans_text[:min(500, len(student_ans_text))] if student_ans_text else "Could not extract text or text is empty.",
        "correct_excerpt": correct_ans_text[:min(500, len(correct_ans_text))] if correct_ans_text else "Could not extract text or text is empty.",
        "similarity_score": submission.score if submission.score is not None else "N/A",
        "grade": submission.grade if submission.grade else "N/A",
        "numerical_score": submission.numerical_score if submission.numerical_score is not None else "N/A"
    }]
    return render_template('results.html', results=evaluated_results)
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
