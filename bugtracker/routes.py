import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from bugtracker import app, db, bcrypt, mail
from bugtracker.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             TicketForm, RequestResetForm, ResetPasswordForm)
from bugtracker.models import User, Ticket
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from flask_paginate import Pagination, get_page_parameter

ticket_severity_class = {
    "minor":"info",
    "functional":"warning",
    "critical":"danger"
}
ticket_state_class = {
    "pending":"primary",
    "working on it":"warning",
    "fixed":"success",
    "rejected":"danger"
}

@app.route("/")
@app.route("/home")
@login_required
def home():
    page = request.args.get('page', default=1, type=int)
    tickets = Ticket.query.order_by(Ticket.date_posted.desc()).paginate(page=page, per_page=10)
    
    return render_template('home.html', tickets=tickets, severity=ticket_severity_class, state=ticket_state_class)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/register_admin", methods=['GET', 'POST'])
def register_admin():
    if not current_user.access=="admin":
        flash('You don\'t have access to that page. You have been returned to the homepage.', 'danger')
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, email=form.email.data, password=hashed_password, access="admin")
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.name = form.name.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.name.data = current_user.name
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/ticket/new", methods=['GET', 'POST'])
@login_required
def create_ticket():
    form = TicketForm()
    if form.validate_on_submit():
        ticket = Ticket(title=form.title.data, content=form.content.data, author=current_user, severity=form.severity.data)
        db.session.add(ticket)
        db.session.commit()
        flash('Your ticket has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_ticket.html', title='New Ticket', form=form)


@app.route("/ticket/<int:ticket_id>")
def ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('ticket.html', ticket=ticket, severity=ticket_severity_class, state=ticket_state_class)


@app.route("/ticket/<int:ticket_id>/update", methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.access != "admin":
        abort(403)
    form = TicketForm()
    if form.validate_on_submit():
        ticket.title = form.title.data
        ticket.content = form.content.data
        ticket.severity = form.severity.data
        ticket.state = form.state.data
        db.session.commit()
        flash('The ticket has been updated!', 'success')
        return redirect(url_for('ticket', ticket_id=ticket.id))
    elif request.method == 'GET':
        form.title.data = ticket.title
        form.content.data = ticket.content
        form.severity.data = ticket.severity
        form.state.data = ticket.state
    return render_template('create_ticket.html', title='Update Ticket',
                           form=form, ticket=ticket)


@app.route("/ticket/<int:ticket_id>/delete", methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.access!="admin":
        abort(403)
    db.session.delete(ticket)
    db.session.commit()
    flash('The ticket has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/user/<string:name>")
def user_tickets(name):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(name=name).first_or_404()
    tickets = Ticket.query.filter_by(author=user)\
        .order_by(Ticket.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_tickets.html', tickets=tickets, user=user)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

