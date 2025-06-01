from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Job, Application, PortfolioItem, Message, Review
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config.from_pyfile('config.py')
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Главная страница
@app.route('/')
def index():
    jobs = Job.query.filter_by(is_active=True).order_by(Job.created_at.desc()).limit(6).all()
    freelancers = User.query.filter_by(is_freelancer=True).order_by(db.func.random()).limit(4).all()
    return render_template('index.html', jobs=jobs, freelancers=freelancers)

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Пользователь с таким именем или email уже существует', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            is_freelancer=(user_type == 'freelancer'),
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Неверный email или пароль', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        flash('Вы успешно вошли в систему', 'success')
        return redirect(url_for('index'))
    
    return render_template('auth/login.html')

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Список заказов
@app.route('/jobs')
def job_list():
    page = request.args.get('page', 1, type=int)
    query = Job.query.filter_by(is_active=True)
    
    # Фильтрация
    category = request.args.get('category')
    if category:
        query = query.filter_by(category=category)
    
    jobs = query.order_by(Job.created_at.desc()).paginate(page=page, per_page=10)
    return render_template('jobs/list.html', jobs=jobs)

# Создание заказа
@app.route('/jobs/create', methods=['GET', 'POST'])
@login_required
def create_job():
    if current_user.is_freelancer:
        flash('Только заказчики могут размещать заказы', 'warning')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        budget = request.form['budget']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        new_job = Job(
            title=title,
            description=description,
            category=category,
            budget=budget,
            deadline=deadline,
            client_id=current_user.id,
            created_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(new_job)
        db.session.commit()
        flash('Заказ успешно создан', 'success')
        return redirect(url_for('job_detail', job_id=new_job.id))
    
    return render_template('jobs/create.html')

# Просмотр заказа
@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
    job = Job.query.get_or_404(job_id)
    if current_user.is_authenticated and current_user.is_freelancer:
        has_applied = Application.query.filter_by(
            job_id=job_id,
            freelancer_id=current_user.id
        ).first() is not None
    else:
        has_applied = False
    
    return render_template('jobs/detail.html', job=job, has_applied=has_applied)

# Подача заявки
@app.route('/jobs/<int:job_id>/apply', methods=['POST'])
@login_required
def apply_job(job_id):
    if not current_user.is_freelancer:
        flash('Только фрилансеры могут подавать заявки', 'warning')
        return redirect(url_for('job_detail', job_id=job_id))
    
    job = Job.query.get_or_404(job_id)
    
    if Application.query.filter_by(job_id=job_id, freelancer_id=current_user.id).first():
        flash('Вы уже подали заявку на этот заказ', 'warning')
        return redirect(url_for('job_detail', job_id=job_id))
    
    proposal = request.form['proposal']
    bid = request.form.get('bid', job.budget)
    
    application = Application(
        job_id=job_id,
        freelancer_id=current_user.id,
        proposal=proposal,
        bid=bid,
        created_at=datetime.utcnow(),
        status='pending'
    )
    
    db.session.add(application)
    db.session.commit()
    flash('Ваша заявка успешно отправлена', 'success')
    return redirect(url_for('job_detail', job_id=job_id))

# Просмотр заявок
@app.route('/jobs/<int:job_id>/applications')
@login_required
def job_applications(job_id):
    job = Job.query.get_or_404(job_id)
    
    if job.client_id != current_user.id:
        flash('Вы не можете просматривать заявки на этот заказ', 'danger')
        return redirect(url_for('index'))
    
    applications = Application.query.filter_by(job_id=job_id).all()
    return render_template('jobs/applications.html', job=job, applications=applications)

# Принятие заявки
@app.route('/applications/<int:app_id>/accept')
@login_required
def accept_application(app_id):
    application = Application.query.get_or_404(app_id)
    job = application.job
    
    if job.client_id != current_user.id:
        flash('Вы не можете принимать эту заявку', 'danger')
        return redirect(url_for('index'))
    
    # Отклоняем все другие заявки
    Application.query.filter_by(job_id=job.id).update({'status': 'rejected'})
    
    # Принимаем выбранную заявку
    application.status = 'accepted'
    job.is_active = False
    job.freelancer_id = application.freelancer_id
    
    db.session.commit()
    flash('Вы успешно приняли заявку', 'success')
    return redirect(url_for('job_applications', job_id=job.id))

# Профиль пользователя
@app.route('/profile/<username>')
def view_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    portfolio_items = PortfolioItem.query.filter_by(user_id=user.id).all()
    
    if user.is_freelancer:
        reviews = Review.query.filter_by(freelancer_id=user.id).all()
        completed_jobs = Job.query.filter_by(freelancer_id=user.id, is_active=False).count()
    else:
        reviews = []
        completed_jobs = Job.query.filter_by(client_id=user.id, is_active=False).count()
    
    return render_template('profiles/view.html', 
                         user=user, 
                         portfolio_items=portfolio_items,
                         reviews=reviews,
                         completed_jobs=completed_jobs)

# Редактирование профиля
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        current_user.bio = request.form.get('bio')
        current_user.skills = request.form.get('skills')
        current_user.location = request.form.get('location')
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename != '':
                filename = f"avatar_{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.split('.')[-1]}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar = filename
        
        db.session.commit()
        flash('Профиль успешно обновлен', 'success')
        return redirect(url_for('view_profile', username=current_user.username))
    
    return render_template('profiles/edit.html')

# Добавление работы в портфолио
@app.route('/portfolio/add', methods=['POST'])
@login_required
def add_portfolio_item():
    if not current_user.is_freelancer:
        flash('Только фрилансеры могут добавлять работы в портфолио', 'warning')
        return redirect(url_for('edit_profile'))
    
    title = request.form['title']
    description = request.form['description']
    url = request.form.get('url', '')
    
    portfolio_item = PortfolioItem(
        user_id=current_user.id,
        title=title,
        description=description,
        url=url,
        created_at=datetime.utcnow()
    )
    
    if 'image' in request.files:
        file = request.files['image']
        if file.filename != '':
            filename = f"portfolio_{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.split('.')[-1]}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            portfolio_item.image = filename
    
    db.session.add(portfolio_item)
    db.session.commit()
    flash('Работа успешно добавлена в портфолио', 'success')
    return redirect(url_for('view_profile', username=current_user.username))

# Сообщения
@app.route('/messages')
@login_required
def inbox():
    conversations = db.session.query(
        Message,
        User
    ).join(
        User,
        (User.id == Message.sender_id) | (User.id == Message.recipient_id)
    ).filter(
        (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id),
        User.id != current_user.id
    ).order_by(
        Message.created_at.desc()
    ).all()
    
    # Уникальные собеседники
    unique_conversations = {}
    for msg, user in conversations:
        if user.id not in unique_conversations:
            unique_conversations[user.id] = {
                'user': user,
                'last_message': msg,
                'unread': False
            }
    
    return render_template('messaging/inbox.html', conversations=unique_conversations.values())

# Диалог
@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    other_user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        content = request.form['content']
        message = Message(
            sender_id=current_user.id,
            recipient_id=user_id,
            content=content,
            created_at=datetime.utcnow(),
            is_read=False
        )
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('conversation', user_id=user_id))
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()
    
    # Помечаем сообщения как прочитанные
    Message.query.filter_by(sender_id=user_id, recipient_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return render_template('messaging/conversation.html', 
                         messages=messages, 
                         other_user=other_user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
