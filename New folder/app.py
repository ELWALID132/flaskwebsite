from flask import Flask,render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from flask_login import LoginManager, login_user, current_user
import smtplib # Import the smtplib module

# Set up the Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Set up the SQLite3 database
db = SQLAlchemy(app)

# send email function
def send_email(to, subject, body):
  # Create an SMTP server object
  server = smtplib.SMTP("localhost")

  # Construct the email message
  msg = f"Subject: {subject}\n\n{body}"

  # Send the email
  server.sendmail("noreply@example.com", to, msg)

  # Close the SMTP server
  server.quit()
  
# Create the user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120),nullable=False)
    def __repr__(self):
        return '<User %r>' % self.username

# the main route
@app.route('/')
def hello_world():
    return render_template("layout.html")

# login route
@app.route("/login", methods=["GET", "POST"])
def login():
    # check if the user reached out by POST method
    if request.method == "POST":

        # get the email and password values from the form
        email = request.form.get("email")
        password = request.form.get("password")

        # make sure that the email is given
        if not request.form.get("email"):
            return flash("Please write your email")

        # make sure that the user wrote his password
        if not request.form.get("password"):
            return flash("Please write your password")

        # Use SQLAlchemy to query the database for a user with the given email and password
        user = User.query.filter_by(email=email, password=password).first()

        if user:
            login_user(user)
            return redirect(url_for("home"))

        # if user not found
        else:
            flash("Invalid email or password")

    # If the request method was GET, show the login form
    return render_template("login.html")

# signup route
@app.route("/singup", methods=["GET", "POST"])
def signup():
    # check if user reaches out via POST method
    if request.method == "POST":

        # get the input information
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        # make sure that the email is given
        if not request.form.get("email"):
            return flash("Please provide an email")

        # make sure that the username is given
        if not request.form.get("username"):
            return flash("Please provide an username")

        # make sure that the user wrote his password
        if not request.form.get("password1"):
            return flash("Please provide a password")

        # make sure that the user confirms his password
        if not request.form.get("password2"):
            return flash("Please confirm your password")

        # Check if the two password inputs match
        if password1 != password2:
            return "Passwords do not match"

        # Check if the provided username or email is already registered
        if User.query.filter(User.username == username).first() is not None:
            return flash("Username is already taken")
        if User.query.filter(User.email == email).first() is not None:
            return flash("Email is already registered")

        # Create a new user
        new_user = User(username=username, email=email, password=password1)

        # Hash the user's password for security
        new_user.set_password(password1)

        # Add the new user to the database and commit the changes
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            return f"An error occurred: {e}"

        return "Signup successful"
    return render_template("singup.html")

# forget password route
@app.route("/resetpassword", methods=["GET", "POST"])
def reset_password():
    # if the user reach out via POST method
    if request.method == "POST":

        # get the input infos
        email = request.form.get("email")

        # make sure that the user has entered their email
        if not email:
            return flash("please provide an email")

        # Use SQLAlchemy to query the database for a user with the given email
        user = User.query.filter_by(email=email).first()
        
        # if user found 
        if user:
            # generate a new random password
            import string
            import random
            new_password = "".join(random.choices(string.ascii_letters + string.digits, k=16))

            # update the user's password in the database
            user.password = new_password

            # commit the change to the database
            db.session.commit()

            # send an email to the user with their new password
            send_email(user.email, "Your new password", f"Your new password is: {new_password}")

            flash("A new password has been sent to your email.")

        else:
            flash("email not found")
            

    return render_template("resetpassword.html")

if __name__ == '__main__':
    app.run(debug = True)
