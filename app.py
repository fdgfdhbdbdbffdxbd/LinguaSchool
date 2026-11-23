from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import csv
import io
import os
import random
import secrets

import click
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for, Response
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from sqlalchemy import UniqueConstraint, CheckConstraint, event
from sqlalchemy.engine import Engine

load_dotenv(Path(__file__).with_name('.env'))
db = SQLAlchemy()
passwords = PasswordHasher()
dummy_hash = passwords.hash(secrets.token_urlsafe(32))

def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

@event.listens_for(Engine, 'connect')
def sqlite_fk(connection, _):
    if connection.__class__.__module__.startswith('sqlite3'):
        connection.execute('PRAGMA foreign_keys=ON')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    phone_cipher = db.Column(db.Text)
    __table_args__ = (CheckConstraint("role in ('student','teacher','admin')"),)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'course_id'),)

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    starts = db.Column(db.DateTime, nullable=False)
    room = db.Column(db.String(100), nullable=False)

class Homework(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=False)
    due = db.Column(db.DateTime, nullable=False)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    homework_id = db.Column(db.Integer, db.ForeignKey('homework.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    grade = db.Column(db.Integer)
    feedback = db.Column(db.Text)
    __table_args__ = (UniqueConstraint('homework_id', 'user_id'), CheckConstraint('grade >= 0 and grade <= 100'),)

class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(10), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    synthetic = db.Column(db.Boolean, default=False, nullable=False)
    __table_args__ = (CheckConstraint('score >= 0 and score <= 100'),)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(80), nullable=False)
    created = db.Column(db.DateTime, default=now, index=True, nullable=False)

class LoginSession(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires = db.Column(db.DateTime, nullable=False)

QUESTIONS = [
    ('She ___ a teacher.', ['am', 'is', 'are'], '1'),
    ('Yesterday we ___ to school.', ['go', 'went', 'gone'], '1'),
    ('I have lived here ___ 2020.', ['for', 'since', 'at'], '1'),
    ('If I had time, I ___ travel.', ['will', 'would', 'am'], '1'),
    ('Choose the synonym of difficult.', ['easy', 'challenging', 'small'], '1'),
    ('He ___ already finished.', ['has', 'have', 'is'], '0'),
    ('This book ___ in 1990.', ['wrote', 'was written', 'writes'], '1'),
    ('I look forward to ___ you.', ['see', 'seeing', 'saw'], '1'),
    ('Neither answer ___ correct.', ['is', 'are', 'be'], '0'),
    ('Had I known, I ___ helped.', ['would have', 'will', 'had'], '0'),
]

def audit(action):
    db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action=action))
    db.session.commit()

def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*a, **kw):
            if current_user.role not in allowed:
                abort(403)
            return fn(*a, **kw)
        return wrapped
    return decorator

def accessible(course):
    return current_user.is_authenticated and (current_user.role == 'admin' or
        (current_user.role == 'teacher' and course.teacher_id == current_user.id) or
        (current_user.role == 'student' and db.session.scalar(db.select(Enrollment).filter_by(user_id=current_user.id, course_id=course.id)) is not None))

def require_course(course_id):
    course = db.get_or_404(Course, course_id)
    if not accessible(course):
        abort(403)
    return course

def value(name, maximum=5000):
    result = request.form.get(name, '').strip()
    if not result or len(result) > maximum:
        abort(400)
    return result

def number(name):
    try:
        return int(request.form[name])
    except (KeyError, ValueError):
        abort(400)

def date_value(name):
    try:
        return datetime.fromisoformat(value(name, 30))
    except ValueError:
        abort(400)

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv('SECRET_KEY'), FIELD_KEY=os.getenv('FIELD_KEY'),
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///school.db'),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE') == '1', PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=65536, SQLALCHEMY_TRACK_MODIFICATIONS=False)
    if config:
        app.config.update(config)
    if not app.config['SECRET_KEY'] or not app.config['FIELD_KEY']:
        raise RuntimeError('Run python configure.py first')
    app.extensions['cipher'] = Fernet(app.config['FIELD_KEY'].encode())
    db.init_app(app)
    login = LoginManager(app)
    login.login_view = 'signin'

    @login.user_loader
    def load_user(uid):
        sid = session.get('sid')
        record = db.session.get(LoginSession, sid) if sid else None
        if record and record.expires > now() and str(record.user_id) == uid:
            return db.session.get(User, record.user_id)
        return None

    CSRFProtect(app)

    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cache-Control'] = 'no-store'
        if app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(CSRFError)
    def csrf_failure(error):
        audit('csrf_blocked')
        return render_template('error.html', code=400, message='Недействительный CSRF-токен. Обновите страницу.'), 400

    @app.errorhandler(403)
    def forbidden(error):
        audit('access_denied')
        return render_template('error.html', code=403, message='Доступ запрещён'), 403

    @app.errorhandler(404)
    def missing(error):
        return render_template('error.html', code=404, message='Страница не найдена'), 404

    @app.route('/')
    def index():
        return render_template('index.html', courses=db.session.scalars(db.select(Course)).all())

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = value('email', 254).lower()
            password = value('password', 128)
            if '@' not in email or len(password) < 12:
                flash('Нужны email и пароль длиной от 12 символов.')
            elif db.session.scalar(db.select(User).filter_by(email=email)):
                flash('Регистрация недоступна для этого адреса.')
            else:
                phone = request.form.get('phone', '').strip()
                if len(phone) > 40:
                    abort(400)
                db.session.add(User(email=email, name=value('name',100), role='student', password_hash=passwords.hash(password),
                    phone_cipher=app.extensions['cipher'].encrypt(phone.encode()).decode() if phone else None))
                db.session.commit()
                flash('Аккаунт создан. Войдите.')
                return redirect(url_for('signin'))
        return render_template('auth.html', register=True)

    @app.route('/login', methods=['GET', 'POST'])
    def signin():
        if request.method == 'POST':
            email = value('email',254).lower()
            user = db.session.scalar(db.select(User).filter_by(email=email))
            # Global persistent limit bounds password hashing abuse in this educational deployment.
            failures = db.session.scalar(db.select(db.func.count(Audit.id)).where(Audit.action == 'login_failed', Audit.created > now()-timedelta(minutes=1)))
            if failures >= 30:
                return render_template('error.html', code=429, message='Слишком много попыток. Подождите минуту.'), 429
            try:
                valid = passwords.verify(user.password_hash if user else dummy_hash, value('password',128))
            except (VerificationError, InvalidHashError):
                valid = False
            if user and valid:
                session.clear()
                sid = secrets.token_hex(32)
                db.session.add(LoginSession(id=sid, user_id=user.id, expires=now()+timedelta(hours=2)))
                db.session.commit()
                session['sid'] = sid
                session.permanent = True
                login_user(user)
                audit('login_success')
                return redirect(url_for('dashboard'))
            audit('login_failed')
            flash('Неверные учётные данные.')
        return render_template('auth.html', register=False)

    @app.post('/logout')
    @login_required
    def signout():
        record = db.session.get(LoginSession, session.get('sid'))
        if record:
            db.session.delete(record)
            db.session.commit()
        logout_user()
        session.clear()
        return redirect(url_for('index'))

    @app.get('/dashboard')
    @login_required
    def dashboard():
        courses = [c for c in db.session.scalars(db.select(Course)).all() if accessible(c)]
        ids = [c.id for c in courses]
        lessons = db.session.scalars(db.select(Lesson).where(Lesson.course_id.in_(ids)).order_by(Lesson.starts)).all()
        attempts = db.session.scalars(db.select(Attempt).filter_by(user_id=current_user.id, synthetic=False).order_by(Attempt.id.desc()).limit(10)).all()
        return render_template('dashboard.html', courses=courses, lessons=lessons, attempts=attempts)

    @app.route('/test', methods=['GET','POST'])
    @roles('student')
    def placement():
        if request.method == 'POST':
            score = sum(request.form.get(f'q{i}') == q[2] for i,q in enumerate(QUESTIONS))*10
            level = 'A1' if score < 40 else 'A2' if score < 70 else 'B1' if score < 90 else 'B2'
            db.session.add(Attempt(user_id=current_user.id, score=score, level=level))
            db.session.commit()
            flash(f'Результат: {score}/100. Рекомендованный учебный уровень: {level}. Тест демонстрационный, не сертификация CEFR.')
            return redirect(url_for('dashboard'))
        return render_template('test.html', questions=QUESTIONS)

    @app.get('/course/<int:course_id>')
    @login_required
    def course(course_id):
        item = require_course(course_id)
        tasks = db.session.scalars(db.select(Homework).filter_by(course_id=course_id)).all()
        return render_template('course.html', course=item, tasks=tasks)

    @app.route('/homework/<int:task_id>', methods=['GET','POST'])
    @login_required
    def homework(task_id):
        task = db.get_or_404(Homework,task_id)
        require_course(task.course_id)
        if request.method == 'POST':
            if current_user.role != 'student': abort(403)
            if now() > task.due:
                flash('Срок сдачи истёк.')
            else:
                row = db.session.scalar(db.select(Submission).filter_by(homework_id=task.id,user_id=current_user.id))
                if row and row.grade is not None:
                    flash('Работа уже оценена.')
                else:
                    if row is None:
                        row = Submission(homework_id=task.id,user_id=current_user.id)
                        db.session.add(row)
                    row.answer = value('answer')
                    db.session.commit()
                    flash('Ответ сохранён.')
            return redirect(request.path)
        query = db.select(Submission).filter_by(homework_id=task.id)
        if current_user.role == 'student': query = query.filter_by(user_id=current_user.id)
        return render_template('homework.html',task=task, submissions=db.session.scalars(query).all())

    @app.post('/grade/<int:submission_id>')
    @roles('teacher','admin')
    def grade(submission_id):
        row = db.get_or_404(Submission,submission_id)
        require_course(db.session.get(Homework,row.homework_id).course_id)
        grade_value = number('grade')
        if not 0 <= grade_value <= 100: abort(400)
        row.grade, row.feedback = grade_value, value('feedback',2000)
        db.session.commit()
        audit('homework_graded')
        return redirect(url_for('homework',task_id=row.homework_id))

    @app.route('/manage', methods=['GET','POST'])
    @roles('teacher','admin')
    def manage():
        if request.method == 'POST':
            action = value('action',30)
            if action == 'course':
                teacher_id = number('teacher_id') if current_user.role == 'admin' else current_user.id
                teacher = db.get_or_404(User,teacher_id)
                if teacher.role != 'teacher': abort(400)
                db.session.add(Course(title=value('title',150),level=value('level',10),content=value('content'),teacher_id=teacher_id))
            elif action in ('homework','lesson','update_course','delete_course'):
                c = require_course(number('course_id'))
                if action == 'homework': db.session.add(Homework(course_id=c.id,title=value('title',150),body=value('body'),due=date_value('due')))
                elif action == 'lesson': db.session.add(Lesson(course_id=c.id,starts=date_value('starts'),room=value('room',100)))
                elif action == 'update_course': c.title, c.content = value('title',150),value('content')
                else:
                    related = sum(db.session.scalar(db.select(db.func.count(model.id)).filter_by(course_id=c.id)) for model in (Enrollment,Lesson,Homework))
                    if related:
                        flash('Удаление возможно только для пустого курса.')
                        return redirect(request.path)
                    db.session.delete(c)
            elif action in ('enroll','role'):
                if current_user.role != 'admin': abort(403)
                user = db.get_or_404(User,number('user_id'))
                if action == 'enroll':
                    c = db.get_or_404(Course,number('course_id'))
                    if user.role != 'student': abort(400)
                    if not db.session.scalar(db.select(Enrollment).filter_by(user_id=user.id,course_id=c.id)):
                        db.session.add(Enrollment(user_id=user.id,course_id=c.id))
                else:
                    role = value('role',20)
                    if role not in ('student','teacher','admin') or user.id == current_user.id: abort(400)
                    user.role = role
                    db.session.execute(db.delete(LoginSession).where(LoginSession.user_id == user.id))
            else: abort(400)
            db.session.commit()
            audit('manage_'+action)
            flash('Изменения сохранены.')
            return redirect(request.path)
        courses = [c for c in db.session.scalars(db.select(Course)).all() if accessible(c)]
        users = db.session.scalars(db.select(User).order_by(User.id)).all() if current_user.role == 'admin' else []
        return render_template('manage.html',courses=courses,users=users)

    @app.get('/analytics')
    @roles('admin')
    def analytics():
        counts = db.session.execute(db.select(Attempt.level,db.func.count(Attempt.id)).group_by(Attempt.level)).all()
        logs = db.session.scalars(db.select(Audit).order_by(Audit.id.desc()).limit(50)).all()
        return render_template('analytics.html', counts=counts,logs=logs,total=sum(c[1] for c in counts))

    @app.get('/analytics.csv')
    @roles('admin')
    def analytics_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['attempt_id','score','level','date','synthetic'])
        for a in db.session.scalars(db.select(Attempt).order_by(Attempt.id)):
            writer.writerow([a.id,a.score,a.level,a.created.isoformat(),a.synthetic])
        return Response('\ufeff'+output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=attempts.csv'})

    @app.cli.command('init-db')
    def init_db():
        db.create_all()
        click.echo('Schema created')

    @app.cli.command('seed')
    def seed():
        db.create_all()
        if db.session.scalar(db.select(User.id).limit(1)):
            raise click.ClickException('Seed requires an empty database')
        credentials=[]
        for role, name in [('admin','Администратор'),('teacher','Анна Смирнова'),('student','Иван Петров'),('student','Мария Орлова')]:
            email = f'{role if role != "student" or not any(x[0] == "student@demo.local" for x in credentials) else "student2"}@demo.local'
            password = secrets.token_urlsafe(15)
            u = User(email=email,name=name,role=role,password_hash=passwords.hash(password),phone_cipher=app.extensions['cipher'].encrypt(b'+70000000000').decode())
            db.session.add(u)
            credentials.append((email,password))
        db.session.flush()
        teacher = db.session.scalar(db.select(User).filter_by(role='teacher'))
        students = db.session.scalars(db.select(User).filter_by(role='student')).all()
        for title,level in [('Английский для начинающих','A1'),('Разговорный английский','B1')]:
            c=Course(title=title,level=level,teacher_id=teacher.id,content='Авторский урок школы LinguaSchool\nPresent Simple: I work. She works.\nПрактика: напишите пять предложений о своём дне.')
            db.session.add(c)
            db.session.flush()
            db.session.add(Enrollment(user_id=students[0].id,course_id=c.id))
            db.session.add(Lesson(course_id=c.id,starts=now()+timedelta(days=c.id,hours=3),room='Аудитория '+str(c.id)))
            db.session.add(Homework(course_id=c.id,title='Мой обычный день',body='Напишите 5–10 предложений на английском языке.',due=now()+timedelta(days=7)))
        rng=random.Random(42)
        for i in range(5000):
            score=rng.randrange(11)*10
            level='A1' if score<40 else 'A2' if score<70 else 'B1' if score<90 else 'B2'
            db.session.add(Attempt(user_id=students[i%2].id,score=score,level=level,created=now()-timedelta(days=rng.randrange(180)),synthetic=True))
        db.session.commit()
        click.echo('5000 synthetic attempts created. SAVE THESE PASSWORDS (shown once):')
        for email,password in credentials: click.echo(f'{email}  {password}')

    return app

# The factory can be imported by tests without creating a default application.
if os.getenv('LINGUA_FACTORY_ONLY') != '1':
    app = create_app()
