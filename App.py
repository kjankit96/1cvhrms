import streamlit as st
import sqlite3
from datetime import date, datetime
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

# --- CONFIGURATION ---
ST_PAGE_TITLE = "1 Cybervalley HRMS"
ACCENT_COLOR = "#1E3A8A"  # blue shade

# Email settings for invites (configure SMTP)
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "noreply@yourdomain.com"
SMTP_PASS = "your_smtp_password"

# --- DATABASE SETUP ---
conn = sqlite3.connect('hrms.db', check_same_thread=False)
c = conn.cursor()
# Users table
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    manager_id INTEGER
)
''')
# Invites table
c.execute('''
CREATE TABLE IF NOT EXISTS invites (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    invited_on DATE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0
)
''')
# Leaves table
c.execute('''
CREATE TABLE IF NOT EXISTS leaves (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    from_date DATE NOT NULL,
    to_date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    requested_on DATE NOT NULL,
    approved_on DATE,
    approved_by INTEGER
)
''')
conn.commit()

# --- UTILITY FUNCTIONS ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, pwd_hash: str) -> bool:
    return hash_password(password) == pwd_hash

def send_invite(email: str, token: str):
    msg = EmailMessage()
    msg['Subject'] = 'You are invited to 1 Cybervalley HRMS'
    msg['From'] = SMTP_USER
    msg['To'] = email
    params = urlencode({'token': token})
    link = st.get_option('server.address') + '?' + params
    msg.set_content(f"Click the link to register: {link}")
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

# --- THEME & PAGE CONFIG ---
st.set_page_config(page_title=ST_PAGE_TITLE, page_icon=":office:")
st.markdown(f"<style>:root {{--accent: {ACCENT_COLOR};}} .css-1d391kg {{background-color: var(--accent)}}</style>", unsafe_allow_html=True)

# --- AUTHENTICATION & SESSIONS ---
if 'user_email' not in st.session_state:
    st.session_state.user_email = None
    st.session_state.role = None

# Registration via invite token
query = st.query_params
if 'token' in query and st.session_state.user_email is None:
    token = query['token'][0]
    invite = c.execute("SELECT email, used FROM invites WHERE token=?", (token,)).fetchone()
    if invite and not invite[1]:
        st.title("Complete Your Registration")
        password = st.text_input("Choose Password", type='password')
        if st.button("Register"):
            pwd_hash = hash_password(password)
            c.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'Member')", (invite[0], pwd_hash))
            c.execute("UPDATE invites SET used=1 WHERE token=?", (token,))
            conn.commit()
            st.success("Registration complete! Please reload to login.")
            st.stop()
    else:
        st.error("Invalid or used token.")
        st.stop()

# --- INITIAL SUPER ADMIN CREATION ---
default_email = "onecybervalley.com"
default_password = "1234"
pwd_hash = hash_password(default_password)
exists = c.execute("SELECT 1 FROM users WHERE email=?", (default_email,)).fetchone()
if not exists:
    c.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", (default_email, pwd_hash, "Super Admin"))
    conn.commit()

# Login form
if st.session_state.user_email is None:
    st.sidebar.title("Login to 1 Cybervalley HRMS")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type='password')
    if st.sidebar.button("Login"):
        user = c.execute("SELECT password_hash, role FROM users WHERE email=?", (email,)).fetchone()
        if user and verify_password(password, user[0]):
            st.session_state.user_email = email
            st.session_state.role = user[1]
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials.")
    st.stop()
else:
    st.sidebar.write(f"Logged in as: {st.session_state.user_email} ({st.session_state.role})")
    if st.sidebar.button("Logout"):
        st.session_state.user_email = None
        st.session_state.role = None
        st.rerun()

# --- PAGES ---
menu = ["Home", "Invite Users", "Employee Calendar", "Apply Leave"]
if st.session_state.role in ["Super Admin", "Admin"]:
    menu += ["Approve Leaves", "Manage Roles"]
page = st.sidebar.selectbox("Menu", menu)

# Home
if page == "Home":
    st.title(ST_PAGE_TITLE)
    st.info("Welcome to the HRMS. Use the sidebar to navigate.")

# Invite Users
elif page == "Invite Users":
    if st.session_state.role == "Super Admin":
        st.title("Invite New User")
        email = st.text_input("Email to invite")
        if st.button("Send Invite"):
            token = secrets.token_urlsafe(16)
            c.execute("INSERT INTO invites (token, email, invited_on) VALUES (?, ?, ?)", (token, email, date.today()))
            conn.commit()
            send_invite(email, token)
            st.success(f"Invite sent to {email}")
    else:
        st.error("Only Super Admin can invite users.")

# Employee Calendar
elif page == "Employee Calendar":
    st.title("Team Calendar")
    # TODO: integrate calendar component to display approved leaves
    leaves = c.execute("SELECT user_id, from_date, to_date FROM leaves WHERE status='Approved'").fetchall()
    st.write("(Calendar view placeholder)")
    st.write(leaves)

# Apply Leave
elif page == "Apply Leave":
    st.title("Apply for Leave")
    leave_type = st.selectbox("Type of Leave", ["Sick", "Casual", "Annual"])
    from_date = st.date_input("From")
    to_date = st.date_input("To")
    if st.button("Submit"):
        user_id = c.execute("SELECT id FROM users WHERE email=?", (st.session_state.user_email,)).fetchone()[0]
        c.execute("INSERT INTO leaves (user_id, type, from_date, to_date, requested_on) VALUES (?, ?, ?, ?, ?)"
                  , (user_id, leave_type, from_date, to_date, date.today()))
        conn.commit()
        st.success("Leave request submitted.")

# Approve Leaves
elif page == "Approve Leaves":
    if st.session_state.role in ["Super Admin", "Admin"]:
        st.title("Approve Pending Leaves")
        pending = c.execute("SELECT l.id, u.email, l.type, l.from_date, l.to_date FROM leaves l JOIN users u ON l.user_id=u.id WHERE status='Pending'").fetchall()
        for lid, email, ltype, start, end in pending:
            if st.button(f"Approve {email} ({ltype}) from {start} to {end}", key=lid):
                c.execute("UPDATE leaves SET status='Approved', approved_on=?, approved_by=(SELECT id FROM users WHERE email=?) WHERE id=?"
                          , (date.today(), st.session_state.user_email, lid))
                conn.commit()
                st.rerun()
    else:
        st.error("Access denied.")

# Manage Roles
elif page == "Manage Roles":
    if st.session_state.role == "Super Admin":
        st.title("Manage User Roles")
        users = c.execute("SELECT id, email, role FROM users").fetchall()
        for uid, email, role in users:
            new_role = st.selectbox(f"Role for {email}", ["Member", "Manager", "Admin", "Super Admin"], index=["Member","Manager","Admin","Super Admin"].index(role), key=uid)
            if new_role != role:
                c.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
                conn.commit()
                st.success(f"Updated {email} to {new_role}")
    else:
        st.error("Only Super Admin can manage roles.")
