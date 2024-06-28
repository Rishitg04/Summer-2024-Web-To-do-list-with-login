from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False  
app.config['SECRET_KEY'] = 'Helicopter'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'     #Redirects user to login page if not logged in and tries to access

"""This function is called by Flask-Login whenever it needs to retrieve the user object that represents
 the currently logged-in user. This usually happens when accessing a route that requires authentication
   or when checking if a user is logged in"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True) 
    username = db.Column(db.String(20),nullable=False,unique = True)
    password = db.Column(db.String(80),nullable=False)

    def __init__(self,username,password):
        self.username = username
        self.password = password

class Task(db.Model):
    id = db.Column(db.Integer,primary_key=True)   #will be automatically generated cuz its primary
    content = db.Column(db.Text)  #will automatically be called content as its not specified
    done = db.Column(db.Boolean, default = False)
    
    def __init__(self,content):
        self.content = content
        self.done = False

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route("/")
def home():
    return render_template("Home.html")

@app.route("/login",methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('taskhome'))
    return render_template("Login.html",form=form)

@app.route("/register",methods = ['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("Register.html",form=form)

#For to do list
@app.route("/taskhome",methods = ['GET','POST'])
@login_required
def taskhome():
    all_tasks = Task.query.all()
    return render_template("To_Do.html",tasks = all_tasks)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/addtask",methods=["POST"])
def add_task():
    content = request.form["content"]
    if not content:
        return "Error"
    
    task = Task(content)
    db.session.add(task)
    db.session.commit()
    return redirect(url_for("taskhome"))

@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return redirect(url_for("taskhome"))

    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("taskhome"))


@app.route('/done/<int:task_id>')
def resolve_task(task_id):
    task = Task.query.get(task_id)

    if not task:
        return redirect(url_for("taskhome"))
    if task.done:
        task.done = False
    else:
        task.done = True

    db.session.commit()
    return redirect(url_for("taskhome"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.9", port=8080,debug=True)
