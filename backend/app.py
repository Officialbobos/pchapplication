import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid
from .decorators import login_required, admin_required
import re
from functools import wraps
from backend.forms import AdminLoginForm
from flask_wtf.csrf import generate_csrf


# Load environment variables from .env file
load_dotenv()

# Determine the absolute path to the frontend folder
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app = Flask(__name__, template_folder=template_dir, static_folder=template_dir)

# Update this line to encode the string into a byte string
app.secret_key = os.getenv('SECRET_KEY')

# --- CONFIGURATION ---
# Create a folder for all uploads (applicant documents and temp attachments)
UPLOAD_FOLDER = os.path.join(template_dir, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create a specific folder for temporary email attachments
ATTACHMENT_FOLDER = os.path.join(UPLOAD_FOLDER, 'temp_attachments')
if not os.path.exists(ATTACHMENT_FOLDER):
    os.makedirs(ATTACHMENT_FOLDER)

#Render URL for the application
app.config['SERVER_NAME'] = 'pchfundingapplication.onrender.com'

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI')

# --- SMTP Configuration for SYSTEM-LEVEL Emails ---
MAIL_SERVER_SYSTEM = os.getenv('MAIL_SERVER_SYSTEM')
MAIL_PORT_SYSTEM = int(os.getenv('MAIL_PORT_SYSTEM'))
MAIL_USE_TLS_SYSTEM = os.getenv('MAIL_USE_TLS_SYSTEM').lower() == 'true'
MAIL_USERNAME_SYSTEM = os.getenv('MAIL_USERNAME_SYSTEM')
MAIL_PASSWORD_SYSTEM = os.getenv('MAIL_PASSWORD_SYSTEM')
ADMIN_EMAIL_SYSTEM = os.getenv('ADMIN_EMAIL_SYSTEM')

# --- SMTP Configuration for USER-LEVEL Emails ---
MAIL_SERVER_USER = os.getenv('MAIL_SERVER_USER')
MAIL_PORT_USER = int(os.getenv('MAIL_PORT_USER'))
MAIL_USE_TLS_USER = os.getenv('MAIL_USE_TLS_USER').lower() == 'true'
MAIL_USERNAME_USER = os.getenv('MAIL_USERNAME_USER')
MAIL_PASSWORD_USER = os.getenv('MAIL_PASSWORD_USER')
ADMIN_EMAIL_USER = os.getenv('ADMIN_EMAIL_USER') # This can be the same as the user sender

# Database setup with pymongo (consistent approach)
client = MongoClient(MONGO_URI)
db = client.get_database('pch_funding_db')
users_collection = db['users']

def create_initial_data():
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email", unique=True)

    if not users_collection.find_one({"username": "pchadmin"}):
        hashed_password = generate_password_hash('admin_password_123')
        users_collection.insert_one({
            "username": "pchadmin",
            "password_hash": hashed_password,
            "role": "admins",
            "email": "pchsubmitinfo@gmail.com"
        })
        print("Admin user created.")

create_initial_data()

def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_system_email(form_data, files):
    """Sends a system-level email with a plain text and HTML body, and attachments."""
    try:
        print("Attempting to send admin email...")
        plain_text_body = "A new application has been submitted. Here are the details:\n\n"
        for key, value in form_data.items():
            if key != 'terms':
                plain_text_body += f"{key.replace('_', ' ').title()}: {value}\n"
        
        html_body = render_template('email_template.html', form_data=form_data, current_year=datetime.now().year)
        
        msg = MIMEMultipart('alternative')
        msg['From'] = MAIL_USERNAME_SYSTEM
        msg['To'] = ADMIN_EMAIL_SYSTEM
        msg['Subject'] = "New PCH Funding Application Submitted"
        
        # Attach both the plain text and HTML versions
        msg.attach(MIMEText(plain_text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        # Add attachments
        for filename, file_path in files.items():
            with open(file_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(file_path)}',
            )
            msg.attach(part)

        # Use 'with' statement for safe server connection
        with smtplib.SMTP(MAIL_SERVER_SYSTEM, MAIL_PORT_SYSTEM) as server:
            if MAIL_USE_TLS_SYSTEM:
                server.starttls()
            server.login(MAIL_USERNAME_SYSTEM, MAIL_PASSWORD_SYSTEM)
            server.send_message(msg)
        
        print("Admin email sent successfully!")
        return True
    except smtplib.SMTPAuthenticationError as auth_error:
        print(f"SMTP Authentication Error: {auth_error}")
        print("ACTION: The username or password in your .env file for the SYSTEM mail is incorrect.")
        return False
    except smtplib.SMTPException as smtp_error:
        print(f"SMTP Error: {smtp_error}")
        print("ACTION: There was a problem with the SMTP connection for SYSTEM mail.")
        return False
    except Exception as e:
        print(f"General Error sending system email: {e}")
        return False

def send_user_message_email(recipient_email, subject, html_body, text_body, attachment_path=None):
    """
    A helper function to send emails to users with both HTML and plain text bodies.
    This function uses the standard library email and smtplib modules.
    """
    try:
        msg = MIMEMultipart('mixed')
        msg['From'] = MAIL_USERNAME_USER
        msg['To'] = recipient_email
        msg['Subject'] = subject

        body_part = MIMEMultipart('alternative')
        body_part.attach(MIMEText(text_body, 'plain'))
        body_part.attach(MIMEText(html_body, 'html'))
        
        msg.attach(body_part)

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {os.path.basename(attachment_path)}",
            )
            msg.attach(part)

        with smtplib.SMTP(MAIL_SERVER_USER, MAIL_PORT_USER) as server:
            if MAIL_USE_TLS_USER:
                server.starttls()
            server.login(MAIL_USERNAME_USER, MAIL_PASSWORD_USER)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Error sending user message email: {e}")
        return False

# Admin routes
def is_admin():
    return 'user_id' in session and session.get('role') == 'admins'

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()

    if form.validate_on_submit():
        # Your form validation logic will go here.
        # When using Flask-WTF, we check form.validate_on_submit()
        # which automatically handles the POST check and CSRF token validation.

        username = form.username.data
        password = form.password.data
        
        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user['password_hash'], password) and user['role'] == 'admins':
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session['username'] = user['username']
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid credentials'
            # Pass the form object back to the template so it can display the CSRF token.
            return render_template('admin/admin_login.html', form=form, error=error)

    # For a GET request, just render the template with the form object.
    return render_template('admin/admin_login.html', form=form)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html', username=session.get('username'))

@app.route('/admin/admin_create_applicant_account', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_applicant_account():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        address = request.form['address']
        business = request.form.get('business', '')
        date_of_birth = request.form.get('date_of_birth', '')

        if users_collection.find_one({"email": email}):
            flash('Error: An account with this email already exists.', 'danger')
            return redirect(url_for('admin_create_applicant_account'))

        hashed_password = generate_password_hash(password)

        applicant_image = request.files.get('applicant_image')
        image_url = ''

        if applicant_image and applicant_image.filename != '':
            filename = secure_filename(applicant_image.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            applicant_image.save(image_path)
            image_url = unique_filename

        applicant_document = {
            "full_name": full_name,
            "username": email,
            "email": email,
            "password_hash": hashed_password,
            "phone": phone,
            "address": address,
            "business": business,
            "date_of_birth": date_of_birth,
            "image_url": image_url,
            "role": "applicants"
        }

        users_collection.insert_one(applicant_document)
        flash('Applicant account created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/admin_create_applicant_account.html')

@app.route('/admin/applicants/edit/<applicant_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_applicant(applicant_id):
    applicant = users_collection.find_one({"_id": ObjectId(applicant_id)})
    
    if request.method == 'POST':
        grant_amount_formatted_str = request.form.get('grant_amount')
        disbursement_amount_formatted_str = request.form.get('disbursement_amount')
        
        try:
            cleaned_grant_amount = re.sub(r'[^\d.]', '', grant_amount_formatted_str) if grant_amount_formatted_str else ''
            grant_amount = float(cleaned_grant_amount) if cleaned_grant_amount else 0.0
        except (ValueError, TypeError):
            grant_amount = 0.0
        
        try:
            cleaned_disbursement_amount = re.sub(r'[^\d.]', '', disbursement_amount_formatted_str) if disbursement_amount_formatted_str else ''
            disbursement_amount = float(cleaned_disbursement_amount) if cleaned_disbursement_amount else 0.0
        except (ValueError, TypeError):
            disbursement_amount = 0.0

        new_data = {
            "application_id": request.form.get('application_id'),
            "application_status": request.form.get('application_status'),
            "status_notes": request.form.get('status_notes'),
            "progress_value": request.form.get('progress_value'),
            "progress_color": request.form.get('progress_color'),
            "grant_amount": grant_amount,
            "grant_amount_formatted": grant_amount_formatted_str,
            "disbursement_amount": disbursement_amount,
            "disbursement_amount_formatted": disbursement_amount_formatted_str,
            "disbursement_method": request.form.get('disbursement_method'),
            "award_letter_content": request.form.get('award_letter_content'),
            "agent_name": request.form.get('agent_name'),
            "agent_email": request.form.get('agent_email'),
            "agent_phone": request.form.get('agent_phone'),
            "agent_facebook": request.form.get('agent_facebook'),
            "full_name": request.form.get('full_name'),
            "email": request.form.get('email'),
            "phone": request.form.get('phone'),
            "address": request.form.get('address'),
            "business": request.form.get('business'),
            "date_of_birth": request.form.get('date_of_birth'),
            "payment_issue_message": request.form.get('payment_issue_message', '')
        }
        
        applicant_image = request.files.get('applicant_image')
        if applicant_image and applicant_image.filename != '':
            filename = secure_filename(applicant_image.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            applicant_image.save(image_path)
            new_data['image_url'] = unique_filename

        agent_image = request.files.get('agent_image')
        if agent_image and agent_image.filename != '':
            filename = secure_filename(agent_image.filename)
            unique_filename = "agent_" + str(uuid.uuid4()) + "_" + filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            agent_image.save(image_path)
            new_data['agent_image_url'] = unique_filename

        if new_data.get('progress_value'):
            new_data['progress_value'] = int(new_data['progress_value'])

        users_collection.update_one({"_id": ObjectId(applicant_id)}, {"$set": new_data})
        flash('Applicant and Agent details updated successfully!', 'success')
        return redirect(url_for('admin_manage_applicants'))
        
    return render_template('admin/admin-edit-applicant.html', applicant=applicant)

@app.route('/admin/applicants/write-letter/<applicant_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_write_letter(applicant_id):
    applicant = users_collection.find_one({"_id": ObjectId(applicant_id)})
    if not applicant:
        flash('Applicant not found.', 'danger')
        return redirect(url_for('admin_manage_applicants'))
        
    if request.method == 'POST':
        letter_content = request.form.get('award_letter_content')
        
        has_grant = applicant.get('grant_amount') is not None
        
        users_collection.update_one(
            {"_id": ObjectId(applicant_id)},
            {"$set": {
                "award_letter_content": letter_content,
                "has_award_letter": True, 
                "has_grant_award": has_grant
            }}
        )
        flash('Grant award letter saved successfully!', 'success')
        return redirect(url_for('admin_edit_applicant', applicant_id=applicant_id))
        
    return render_template('admin/admin-write-letter.html', applicant=applicant)

# --- APPLICANT ROUTES ---
@app.route('/applicant/continuous-application')
@login_required
def continuous_application():
    user_id = session.get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return redirect(url_for('applicant_logout'))

    return render_template(
        'applicants/continuous-application.html', 
        user=user, 
        today=datetime.now()
    )

@app.route('/submit_disbursement_details', methods=['POST'])
@login_required
def submit_disbursement_details():
    user_id = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('applicant_login'))

    disbursement_method = request.form.get('disbursement_method')
    disbursement_details = {'method': disbursement_method}

    if disbursement_method == 'Cash':
        disbursement_details['mailing_address'] = request.form.get('cash_mailing_address')
    elif disbursement_method == 'Check':
        disbursement_details['mailing_address'] = request.form.get('check_mailing_address')
    elif disbursement_method == 'Direct Deposit':
        disbursement_details['bank_name'] = request.form.get('bank_name')
        disbursement_details['account_holder_name'] = request.form.get('account_holder_name')
        disbursement_details['account_number'] = request.form.get('account_number')
        disbursement_details['routing_number'] = request.form.get('routing_number')
        disbursement_details['account_type'] = request.form.get('account_type')
        disbursement_details['receipt_address'] = request.form.get('receipt_address')
    elif disbursement_method == 'Bitcoin Address':
        disbursement_details['bitcoin_address'] = request.form.get('bitcoin_address')
    
    session['temp_disbursement_details'] = disbursement_details
    flash('Disbursement details temporarily saved. Please confirm payment.', 'info')
    
    return redirect(url_for('disbursement_confirmation'))


@app.route('/applicant/payment-fee')
@login_required
def disbursement_confirmation():
    user_id = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('applicant_login'))
    
    temp_details = session.get('temp_disbursement_details')

    if not temp_details:
        flash("Disbursement details not found. Please submit them again.", 'warning')
        return redirect(url_for('continuous_application'))
    
    return render_template(
        'applicants/payment-fee.html', 
        user=user,
        temp_disbursement_details=temp_details
    )

@app.route('/finalize_disbursement', methods=['POST'])
@login_required
def finalize_disbursement():
    user_id = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    temp_details = session.get('temp_disbursement_details')
    
    if not user or not temp_details:
        flash('An error occurred. Please submit your details again.', 'error')
        return redirect(url_for('continuous_application'))
    
    payment_successful = True # Assume payment is successful for demonstration
    
    if payment_successful:
        try:
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "disbursement_details": temp_details,
                        "disbursement_details_submitted_at": datetime.now(),
                        "disbursement_fee_paid": True
                    }
                }
            )
            session.pop('temp_disbursement_details', None)
            flash('Disbursement details submitted successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while saving your details: {e}', 'error')
    else:
        flash('Payment failed. Please try again.', 'error')
        return redirect(url_for('disbursement_confirmation'))

    return redirect(url_for('continuous_application'))


@app.route('/admin/applicants/delete/<applicant_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_applicant(applicant_id):
    users_collection.delete_one({"_id": ObjectId(applicant_id)})
    flash('Applicant deleted successfully!', 'success')
    return redirect(url_for('admin_manage_applicants'))


# Consolidated function for sending a newsletter
@app.route('/admin/send_user_message', methods=['GET', 'POST'])
@login_required
@admin_required
def send_newsletter_route():
    """
    Renders the form to send a newsletter (GET)
    and handles the form submission (POST).
    """
    if request.method == 'POST':
        recipient_emails_str = request.form.get('recipient_emails', '')
        subject = request.form.get('subject')
        message_body = request.form.get('message_body')
        include_credentials = 'include_credentials' in request.form
        
        if not recipient_emails_str or not subject or not message_body:
            flash('Recipient emails, subject, and message body are required.', 'danger')
            return redirect(url_for('send_newsletter_route'))

        # Parse the comma-separated emails
        recipient_emails = [email.strip() for email in recipient_emails_str.split(',') if email.strip()]

        # Initialize attachment path
        attachment_path = None
        file = request.files.get('attachment')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            attachment_path = os.path.join(ATTACHMENT_FOLDER, filename)
            file.save(attachment_path)

        # Conditional logic to choose the email template
        if include_credentials:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            login_link = request.form.get('login_link', '')

            # Render a professional email with credentials
            html_body = render_template('admin/email_with_credentials.html', 
                                         subject=subject,
                                         message_body=message_body,
                                         username=username,
                                         password=password,
                                         login_link=login_link,
                                         current_year=datetime.now().year)

            text_body = f"""
Dear Applicant,

{message_body}

Your account credentials are:
Username: {username}
Password: {password}

Go to Login Page: {login_link}

Best regards,
The PCH Funding Team
"""
        else:
            # Render a simple newsletter template
            html_body = render_template('admin/newsletter_template.html', 
                                         message_body=message_body,
                                         subject=subject,
                                         current_year=datetime.now().year)
            
            text_body = f"Subject: {subject}\n\n{message_body}"

        # Send the email to each recipient
        success_count = 0
        fail_count = 0
        for email in recipient_emails:
            if send_user_message_email(email, subject, html_body, text_body, attachment_path):
                success_count += 1
            else:
                fail_count += 1
        
        if attachment_path and os.path.exists(attachment_path):
            os.remove(attachment_path)
            
        if success_count > 0:
            flash(f'Message sent to {success_count} recipients.', 'success')
        if fail_count > 0:
            flash(f'Failed to send message to {fail_count} recipients.', 'danger')

        return redirect(url_for('send_newsletter_route'))
        
    return render_template('admin/send_newsletter.html')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/manage_applicants')
@login_required
@admin_required
def admin_manage_applicants():
    applicants = users_collection.find({"role": "applicants"})
    return render_template('admin/admin_manage_applicants.html', applicants=applicants)

# Applicant routes
def is_applicant():
    return 'user_id' in session and session.get('role') == 'applicants'

@app.route('/applicant/login', methods=['GET', 'POST'])
def applicant_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = users_collection.find_one({"email": email, "role": "applicants"})

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session['email'] = user['email']
            session['full_name'] = user.get('full_name', user['email']) 
            
            return redirect(url_for('applicant_dashboard'))
        else:
            error = 'Invalid credentials'
            return render_template('applicants/applicants-login.html', error=error)
    return render_template('applicants/applicants-login.html')

@app.route('/applicant/dashboard')
@login_required
def applicant_dashboard():
    user_id = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        session.clear()
        return redirect(url_for('applicant_login'))

    return render_template('applicants/applicant_dashboard.html', user=user)

@app.route('/applicant/logout')
def applicant_logout():
    session.clear()
    return redirect(url_for('applicant_login'))

# Public routes
@app.route('/')
def main_homepage():
    return render_template('index.html')

@app.route('/registration_form', methods=['GET', 'POST'])
def registration_form():
    if request.method == 'POST':
        try:
            # Retrieve all form data
            form_data = request.form.to_dict()
            
            # Retrieve and process needs (checkboxes)
            needs = request.form.getlist('needs[]')
            
            # Retrieve social media handles
            social_platforms = request.form.getlist('social_platform[]')
            social_handles = request.form.getlist('social_handle[]')
            social_media_list = []
            for platform, handle in zip(social_platforms, social_handles):
                if platform and handle:
                    social_media_list.append({'platform': platform, 'handle': handle})
            
            email = form_data.get('email')

            # Check if user already exists based on email
            if users_collection.find_one({"email": email}):
                return jsonify({'status': 'error', 'message': 'An account with this email already exists.'}), 409
            
            # File handling
            government_id_file = request.files.get('government_id')
            selfie_photo_file = request.files.get('selfie_photo')
            gov_id_filename = str(uuid.uuid4()) + "_" + secure_filename(government_id_file.filename) if government_id_file and government_id_file.filename else None
            
            # --- FIX: Changed 'selfer_filename' to 'selfie_filename' to match the key below ---
            selfie_filename = str(uuid.uuid4()) + "_" + secure_filename(selfie_photo_file.filename) if selfie_photo_file and selfie_photo_file.filename else None

            # Construct the new user document (this will be the application record)
            new_user = {
                "first_name": form_data.get('first_name', ''),
                "last_name": form_data.get('last_name', ''),
                "full_address": form_data.get('full_address', ''),
                "text_number": form_data.get('text_number', ''),
                "sex": form_data.get('sex', ''),
                "age": int(form_data.get('age', 0)) if form_data.get('age') else 0,
                "occupation": form_data.get('occupation', ''),
                "education_level": form_data.get('education_level', ''),
                "residency": form_data.get('residency', ''),
                "email": email,
                "payment_method": form_data.get('payment_method', ''),
                "currency_symbol": form_data.get('currency_symbol', ''),
                "monthly_income": float(form_data.get('monthly_income', 0)) if form_data.get('monthly_income') else 0.0,
                "how_heard": form_data.get('how_heard', ''),
                "social_media": social_media_list,
                "physical_challenges": form_data.get('physical_challenges', ''),
                "needs": needs,
                "government_id_path": gov_id_filename,
                "selfie_photo_path": selfie_filename,
                "role": "applicants",
                "created_at": datetime.now()
            }
            
            # Save files
            if government_id_file and gov_id_filename:
                gov_id_path = os.path.join(app.config['UPLOAD_FOLDER'], gov_id_filename)
                government_id_file.save(gov_id_path)
            
            if selfie_photo_file and selfie_filename:
                selfie_path = os.path.join(app.config['UPLOAD_FOLDER'], selfie_filename)
                selfie_photo_file.save(selfie_path)

            users_collection.insert_one(new_user)
            
            # Prepare files for admin email attachment
            files = {}
            if gov_id_filename: files['government_id'] = os.path.join(app.config['UPLOAD_FOLDER'], gov_id_filename)
            if selfie_filename: files['selfie_photo'] = os.path.join(app.config['UPLOAD_FOLDER'], selfie_filename)

            # Send a system email to admin with form data and attachments
            send_system_email(new_user, files)
            
            # Return a success message for the frontend
            return jsonify({'status': 'success', 'message': 'Application submitted successfully. We will contact you soon.'})

        except Exception as e:
            print(f"An error occurred during form submission: {e}")
            return jsonify({'status': 'error', 'message': f'An error occurred during submission: {e}'}), 500

    return render_template('registration_form.html')

# Define the route for the 'About Us' page
@app.route('/about-us')
def about_us():
    # Renders the about-us.html template
    return render_template('about-us.html')

if __name__ == '__main__':
    app.run(debug=True)