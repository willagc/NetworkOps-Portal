from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.github import make_github_blueprint, github
from netmiko import ConnectHandler
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Flask app and database setup
app = Flask(__name__)
app.secret_key = "netproxy"
blueprint = make_github_blueprint(
    client_id="my-key-here",
    client_secret="my-secret-here",
)
app.register_blueprint(blueprint, url_prefix="/login")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Device model for storing managed network devices
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    key_path = db.Column(db.String(200), nullable=False)
    device_type = db.Column(db.String(100), nullable=False)
    logs = db.relationship('CommandLog', backref='device', lazy=True)

# User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    logs = db.relationship('CommandLog', backref='user', lazy=True)
    is_sso = db.Column(db.Boolean, default=False)

# Log of commands executed by users on devices
class CommandLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    command = db.Column(db.String(255), nullable=False)
    output = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Decorator to protect routes that require authentication
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper

# Home dashboard
@app.route('/')
@login_required
def index():
    return render_template("index.html")

# View all devices
@app.route("/devices")
@login_required
def list_devices():
    devices = Device.query.all()
    return render_template("devices.html", devices=devices)

# Add a new device to the database
@app.route("/add_device", methods=["GET", "POST"])
@login_required
def add_device():
    if request.method == "POST":
        device = Device(
            name=request.form["name"],
            ip=request.form["ip"],
            username=request.form["username"],
            key_path=request.form["key_path"],
            device_type=request.form["device_type"]
        )
        db.session.add(device)
        db.session.commit()
        return redirect(url_for("list_devices"))
    return render_template("add_device.html")

# Execute a command on a selected device
@app.route("/run_command", methods=["GET", "POST"])
@login_required
def run_command():
    devices = Device.query.all()
    output = None

    if request.method == "POST":
        device_id = request.form["device_id"]
        command = request.form["command"]
        device = Device.query.get(device_id)

        connection_info = {
            "device_type": device.device_type,
            "ip": device.ip,
            "username": device.username,
            "use_keys": True,
            "key_file": device.key_path,
        }

        try:
            # Connect and execute command
            net_connect = ConnectHandler(**connection_info)
            output = net_connect.send_command(command)
            net_connect.disconnect()

            # Save the command log
            log = CommandLog(
                user_id=session["user_id"],
                device_id=device.id,
                command=command,
                output=output
            )
            db.session.add(log)
            db.session.commit()

        except Exception as e:
            output = f"Error: {e}"

    return render_template("run_command.html", devices=devices, output=output)

# Edit an existing device
@app.route("/edit_device/<int:device_id>", methods=["GET", "POST"])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)

    if request.method == "POST":
        device.name = request.form["name"]
        device.ip = request.form["ip"]
        device.username = request.form["username"]
        device.key_path = request.form["key_path"]
        device.device_type = request.form["device_type"]
        db.session.commit()
        return redirect(url_for("list_devices"))

    return render_template("edit_device.html", device=device)

# Delete a device from the database
@app.route("/delete_device/<int:device_id>")
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return redirect(url_for("list_devices"))

# View supported device types
@app.route("/supported_devices")
def supported_devices():
    return render_template("supported_devices.html")

# One-time route to create an initial admin user
@app.route("/create_user")
@login_required
def create_user():
    user = User(username="admin", password_hash=generate_password_hash("admin123"))
    db.session.add(user)
    db.session.commit()
    return "User created"

# Login view
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password_hash, request.form["password"]):
            session["user_id"] = user.id
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html", error=None)

# Logout view
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# View command logs
@app.route("/logs")
@login_required
def view_logs():
    logs = CommandLog.query.order_by(CommandLog.timestamp.desc()).all()
    return render_template("logs.html", logs=logs)

# GitHub OAuth route
@app.route("/github_login")
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if not resp.ok:
        return "GitHub authentication failed", 403

    github_username = resp.json()["login"]
    user = User.query.filter_by(username=github_username).first()

    # If user doesn't exist, create one (no password needed)
    if not user:
        user = User(username=github_username, password_hash="")  # mark as SSO
        db.session.add(user)
        db.session.commit()

    session["user_id"] = user.id
    return redirect(url_for("index"))

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create default admin user if it doesn't exist
        if not User.query.filter_by(username="admin").first():
            default_admin = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                is_sso=False
            )
            db.session.add(default_admin)
            db.session.commit()
            print("[*] Default admin user created: admin / admin123")
        else:
            print("[*] Admin user already exists.")
    app.run(debug=True)