import os
import sys
import csv
import time
import string
import secrets
from datetime import datetime

# ==========================================
# CONFIGURATION & DIRECTORY SETUP
# ==========================================
# Simulating a Linux server environment on your local Windows desktop
BASE_DIR = os.path.abspath("simulated_linux_server")
WATCH_DIR = os.path.join(BASE_DIR, "hr_incoming")       # Where HR drops the CSV
HOME_DIR = os.path.join(BASE_DIR, "home")               # Simulated user home directories
ETC_DIR = os.path.join(BASE_DIR, "etc")                 # Simulated system config (/etc/passwd)
LOG_DIR = os.path.join(BASE_DIR, "var/log")             # Audit logs

# Ensure all simulated Linux directories exist locally
for folder in [WATCH_DIR, HOME_DIR, ETC_DIR, LOG_DIR]:
    os.makedirs(folder, exist_ok=True)

MOCK_PASSWD_FILE = os.path.join(ETC_DIR, "passwd")
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "provisioning_audit.log")

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def log_event(message):
    """Appends system activities to an audit log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    print(log_entry.strip())
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(log_entry)

def generate_username(first_name, last_name):
    """Generates a corporate standardized username: jsmith (first initial + last name)."""
    clean_first = "".join(c for c in first_name if c.isalnum()).lower()
    clean_last = "".join(c for c in last_name if c.isalnum()).lower()
    return f"{clean_first[0]}{clean_last}"

def generate_temp_password(length=12):
    """Generates a secure, random temporary password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ==========================================
# CORE PROVISIONING ENGINE LOGIC
# ==========================================
def provision_user(first_name, last_name, department):
    username = generate_username(first_name, last_name)
    user_home = os.path.join(HOME_DIR, username)
    
    # 1. Check if user already exists in our simulated database
    if os.path.exists(MOCK_PASSWD_FILE):
        with open(MOCK_PASSWD_FILE, "r") as f:
            if f"{username}:" in f.read():
                log_event(f"SKIPPED: User '{username}' already exists in system database.")
                return

    # 2. Mock OS-Level Password/Account Provisioning
    temp_password = generate_temp_password()
    # Mocking standard Linux /etc/passwd format -> username:password:UID:GID:GECOS:home:shell
    mock_uid = secrets.randbelow(4000) + 1000
    passwd_entry = f"{username}:x:{mock_uid}:{mock_uid}:{first_name} {last_name},{department}:{user_home}:/bin/bash\n"
    
    with open(MOCK_PASSWD_FILE, "a") as f:
        f.write(passwd_entry)

    # 3. Provision Local Home Directory & Set Permissions
    os.makedirs(user_home, exist_ok=True)
    # Simulated permission setting (Read/Write/Execute for owner, blocked for others)
    with open(os.path.join(user_home, ".bashrc"), "w") as f:
        f.write(f"# Bash profile for {username}\nprint('Welcome to the corporate network!')\n")

    log_event(f"SUCCESS: Account created for {first_name} {last_name} -> Username: {username} (UID: {mock_uid})")
    log_event(f"SECURITY: Temporary password generated for {username}: [ {temp_password} ] *Expiring status set*")

def process_hr_file(file_path):
    """Parses incoming HR CSV records and triggers account creation."""
    log_event(f"START: Processing incoming HR roster data file: {os.path.basename(file_path)}")
    try:
        with open(file_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Expecting columns: FirstName, LastName, Department
                if 'FirstName' in row and 'LastName' in row:
                    provision_user(row['FirstName'].strip(), row['LastName'].strip(), row.get('Department', 'General').strip())
                else:
                    log_event("ERROR: Missing required 'FirstName' or 'LastName' columns in CSV row.")
        
        # Clean up processed file to prevent reprocessing loops
        os.remove(file_path)
        log_event("FINISHED: HR roster file successfully fully executed and safely removed.")
    except Exception as e:
        log_event(f"FATAL: Error processing file: {str(e)}")

# ==========================================
# DIRECTORY MONITORING LOOP
# ==========================================
def main():
    log_event("ENGINE ACTIVE: Automated Provisioning Daemon is watching folder...")
    log_event(f"MONITORING PATH: {WATCH_DIR}")
    log_event("Drop a roster CSV file containing 'FirstName,LastName,Department' here to watch it automate.")
    
    try:
        while True:
            # Poll folder for new files (Lightweight, native solution for seamless cross-platform execution)
            files = [os.path.join(WATCH_DIR, f) for f in os.listdir(WATCH_DIR) if f.endswith('.csv')]
            for file in files:
                # Small buffer sleep to ensure file transfer from HR completed fully
                time.sleep(1)
                process_hr_file(file)
            time.sleep(2)
    except KeyboardInterrupt:
        log_event("ENGINE SHUTDOWN: Monitored daemon stopped via admin prompt execution command.")

if __name__ == "__main__":
    main()
