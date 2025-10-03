my_flask_app/
│
├── app.py
│   └──
        from flask import Flask, render_template, redirect, url_for, flash, session
        from flask_sqlalchemy import SQLAlchemy
        from werkzeug.security import generate_password_hash, check_password_hash
        from forms import RegistrationForm, LoginForm, ContactFor
        from models import db, User, Message
         import models
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'supersecretkey'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        db.init_app(app)

        @app.before_first_request in 
        def create_tables():
            db.create_all()

 def home():

        @app.route('/')
        def home():
            return render_template('index.html', title='Home')

        @app.route('/about')
        def about():
            return render_template('about.html', title='About')

        @app.route('/contact', methods=['GET', 'POST'])
        def in contact():
            form = ContactForm()
            if form.validate_on_submit():
                msg = Message(name=form.name.data, email=form.email.data, message=form.message.data)
                db.session.add(msg)
                db.session.commit()
                flash('Thank you! Your message has been saved.', 'success')
                return redirect(url_for('contact'))
            return render_template('contact.html', title='Contact', form=form)

        @app.route('/register', methods=['GET', 'POST'])
        def register():
            form = RegistrationForm()
            if form.validate_on_submit():
                hashed_pw = generate_password_hash(form.password.data)
                new_user = User(username=form.username.data, password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            return render_template('register.html', title='Register', form=form)

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            form = LoginForm()
            if form.validate_on_submit():
                user = User.query.filter_by(username=form.username.data).first()
                if user and check_password_hash(user.password, form.password.data):
                    session['logged_in'] = True
                    session['username'] = user.username
                    flash('Login successful!', 'success')
                    return redirect(url_for('admin'))
                else:
                    flash('Invalid credentials', 'danger')
            return render_template('login.html', title='Login', form=form)

        @app.route('/logout')
        def logout():
            session.clear()
            flash('You have been logged out.', 'info')
            return redirect(url_for('home'))

        @app.route('/admin')
        def admin():
            if not session.get('logged_in'):
                flash('Please log in to access admin dashboard.', 'warning')
                return redirect(url_for('login'))
            messages = Message.query.order_by(Message.id.desc()).all()
            return render_template('admin.html', title='Admin Dashboard', messages=messages)

        if __name__ == '__main__':
            app.run(debug=True)

├── models.
│   └──
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy()

        class User(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(150), unique=True, nullable=False)
            password = db.Column(db.String(255), nullable=False)

        class Message(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(150), nullable=False)
            email = db.Column(db.String(150), nullable=False)
            message = db.Column(db.Text, nullable=False)

├── forms.py
│   └──
        from flask_wtf import FlaskForm
        from wtforms import StringField, PasswordField, SubmitField, TextAreaField
        from wtforms.validators import DataRequired, Email, Length

        class RegistrationForm(FlaskForm):
            username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
            password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
            submit = SubmitField('Register')

        class LoginForm(FlaskForm):
            username = StringField('Username', validators=[DataRequired()])
            password = PasswordField('Password', validators=[DataRequired()])
            submit = SubmitField('Login')

        class ContactForm(FlaskForm):
            name = StringField('Name', validators=[DataRequired()])
            email = StringField('Email', validators=[DataRequired(), Email()])
            message = TextAreaField('Message', validators=[DataRequired()])
            submit = SubmitField('Send')

├── templates/
│   ├── base.html
│   │   └──
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>{{ title if title else "Flask App" }}</title>
                  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                  <div class="container">
                    <a class="navbar-brand" href="/">Flask App</a>
                    <div>
                      <a class="nav-link d-inline text-white" href="/">Home</a>
                      <a class="nav-link d-inline text-white" href="/about">About</a>
                      <a class="nav-link d-inline text-white" href="/contact">Contact</a>
                      {% if session.get('logged_in') %}
                        <a class="nav-link d-inline text-warning" href="/admin">Admin</a>
                        <a class="nav-link d-inline text-danger" href="/logout">Logout</a>
                      {% else %}
                        <a class="nav-link d-inline text-info" href="/login">Login</a>
                        <a class="nav-link d-inline text-success" href="/register">Register</a>
                      {% endif %}
                    </div>
                  </div>
                </nav>
                <div class="container mt-4">
                  {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                      {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                      {% endfor %}
                    {% endif %}
                  {% endwith %}
                  {% block content %}{% endblock %}
                </div>
                </body>
                </html>
│
│   ├── index.html
│   │   └──
                {% extends "base.html" %}
                {% block content %}
                <h1>Welcome to the Flask App</h1>
                <p class="lead">Now with secure user authentication and an admin dashboard.</p>
                {% endblock %}
│
│   ├── about.html
│   │   └──
                {% extends "base.html" %}
                {% block content %}
                <h1>About</h1>
                <p>This app demonstrates Flask with authentication, database integration, and Bootstrap styling.</p>
                {% endblock %}
│
│   ├── contact.html
│   │   └──
                {% extends "base.html" %}
                {% block content %}
                <h1>Contact Us</h1>
                <form method="POST">
                    {{ form.hidden_tag() }}
                    <div class="mb-3">
                        {{ form.name.label(class="form-label") }}
                        {{ form.name(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        {{ form.message.label(class="form-label") }}
                        {{ form.message(class="form-control", rows="4") }}
                    </div>
                    {{ form.submit(class="btn btn-primary") }}
                </form>
                {% endblock %}
│
│   ├── login.html
│   │   └──
                {% extends "base.html" %}
                {% block content %}
                <h1>Login</h1>
                <form method="POST">
                    {{ form.hidden_tag() }}
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                    </div>
                    {{ form.submit(class="btn btn-success") }}
                </form>
                {% endblock %}
│
│   ├── register.html
│   │   └──
                {% extends "base.html" %}
                {% block content %}
                <h1>Register</h1>
                <form method="POST">
                    {{ form.hidden_tag() }}
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                    </div>
                    {{ form.submit(class="btn btn-primary") }}
                </form>
                {% endblock %}
│
│   └── admin.html
│       └──
                {% extends "base.html" %}
                {% block content %}
                <h1>Admin Dashboard</h1>
                {% if messages %}
                    <table class="table table-bordered">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for msg in messages %}
                                <tr>
                                    <td>{{ msg.id }}</td>
                                    <td>{{ msg.name }}</td>
                                    <td>{{ msg.email }}</td>
                                    <td>{{ msg.message }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>No messages found.</p>
                {% endif %}
                {% endblock %}

└── requirements.txt
    └──
        Flask
        Flask-WTF
        Flask-SQLAlchemy
        Werkzeug
