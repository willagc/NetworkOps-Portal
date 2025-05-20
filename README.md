# 🐭 Rodent

**Rodent** is an open-source proxy and auditing tool for managing network devices securely. It wraps around [Netmiko](https://github.com/ktbyers/netmiko) and provides a web-based interface with logging, user authentication, and role-based access.

---

## 🚀 Features

- Web UI for executing commands on network devices
- Audit logging with timestamp and user ID
- Role-based access (admin/user)
- GitHub SSO + local login
- Device inventory with editable fields
- Netmiko-powered command execution
- Default admin account created on first run

---

## 🧰 Requirements

- Python 3.8+
- SQLite (bundled)
- SSH keys preconfigured for device access

---

## 🔧 Setup

1. **Clone the repo**

```bash
git clone https://github.com/yourusername/rodent.git
cd rodent
```

2. **Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Run the app**

```bash
python app.py
```

> On first launch, a default admin account is created:
> - **Username:** `admin`
> - **Password:** `admin123`

---

## 🔑 Authentication

Rodent supports:

- ✅ Local login (username/password)
- ✅ GitHub SSO via [Flask-Dance](https://github.com/singingwolfboy/flask-dance)

To enable GitHub login, set up your OAuth keys and update:

```python
blueprint = make_github_blueprint(
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

---

## 📓 Command Logging

All command output and metadata (user, timestamp, device) are stored in the `CommandLog` table and viewable under `/logs`.

---

## 📡 Roadmap

- [ ] Multi-device batch execution
- [ ] Async backend (Scrapli or AsyncSSH)
- [ ] RBAC enforcement per-device
- [ ] Encrypted secret storage

---

## 💬 Contributing

PRs welcome. Please fork, branch, and open a pull request with clear commit messages.

---

## 🧪 Disclaimer

Rodent is in early development. Do **not** use in production without review.

---

## 📛 Name

“Rodent” is a working title. Suggestions welcome.
