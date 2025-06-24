import subprocess
import os
import json
import platform
from pathlib import Path
from datetime import datetime
import re
import sys

STATE_FILE = "setup_state.json"
STEPS = [
    "venv_created",
    "venv_activated",
    "requirements_installed",
    "env_updated",
    "migrated",
    "contenttypes_cleared",
    "data_loaded",
    "superuser_created",
    "server_started"
]

LOG_FILE = "setup_log.txt"

# ANSI color codes
COLORS = {
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "cyan": "\033[96m",
    "reset": "\033[0m"
}

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def log(message, color=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored = f"{COLORS.get(color, '')}[{timestamp}] {message}{COLORS['reset'] if color else ''}"
    plain = ANSI_ESCAPE.sub('', colored)

    print(colored)
    with open(LOG_FILE, "a") as f:
        f.write(plain + "\n")

def load_state():
    if Path(STATE_FILE).exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {step: False for step in STEPS}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def mark_done(state, step):
    state[step] = True
    save_state(state)

def cleanup_state_file():
    if Path(STATE_FILE).exists():
        Path(STATE_FILE).unlink()
    
    if Path(LOG_FILE).exists():
        Path(LOG_FILE).unlink()

def run_command(command, env=None, shell=True):
    log(f"\n-> Running: {command}", color="cyan")
    try:
        with subprocess.Popen(
            command,
            shell=shell,
            env=env,
            # stdout=subprocess.PIPE,
            # stderr=subprocess.STDOUT,
            bufsize=1,
            # text=True
        ) as process, open(LOG_FILE, "a") as logfile:
            if process.stdout:
                for line in process.stdout:
                    print(line, end='')  # Keeps color in terminal (if subprocess outputs it)
                    logfile.write(ANSI_ESCAPE.sub('', line))  # Strip colors for log

        if process.returncode != 0:
            log(f"Command failed with exit code {process.returncode}", "red")
            return False
        return True
    except Exception as e:
        log(f"Exception during command execution: {e}", "red")
        return False

def create_virtualenv():
    if not Path("venv").exists():
        log("Creating virtual environment...")
        return run_command("python -m venv venv")
    else:
        log("Virtual environment already exists.")
        return True

def is_venv_active():
    # Checks whether we're inside a virtual environment
    return (
        hasattr(sys, 'real_prefix') or
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    )

def activate_virtualenv(state):
    if is_venv_active():
        log("Virtual environment is active.", "green")
        mark_done(state, "venv_activated")
        return True
    else:
        log("Virtual environment not active.", "yellow")
        log("Please activate the virtual environment manually and re-run the script.\n", "cyan")
        venv_path = Path("venv")
        if platform.system() == "Windows":
            activate_path = venv_path / "Scripts" / "activate"
        else:
            activate_path = venv_path / "bin" / "activate"
        log(f"Run this command in your terminal:\n\n    source {activate_path}\n", "yellow")
        return False

def install_requirements():
    if not Path("requirements.txt").exists():
        log("requirements.txt not found.")
        return False
    return run_command("pip install -r requirements.txt")

def update_env_file():
    env_path = Path(".env")
    if not env_path.exists():
        log(".env file not found.")
        return False

    log("Enter database credentials:")
    db_name = input("Database Name: ")
    db_user = input("Database User: ")
    db_password = input("Database Password: ")
    db_host = input("Database Host (default: localhost: ") or "localhost"
    # db_port = input("Database Port (default: 5432): ") or "5432"

    replacements = {
        "DEV_DATABASE_NAME": db_name,
        "DEV_DATABASE_USER": db_user,
        "DEV_DATABASE_PASSWORD": db_password,
        "DEV_DATABASE_HOST": db_host,
        # "DB_PORT": db_port,
    }

    lines = env_path.read_text().splitlines()
    updated_lines = []

    for line in lines:
        key = line.split('=')[0].strip()
        if key in replacements:
            updated_lines.append(f"{key}={replacements[key]}")
        else:
            updated_lines.append(line)

    env_path.write_text("\n".join(updated_lines) + "\n")
    log(".env file updated.")
    return True

def run_migrations():
    return run_command("python manage.py migrate")

def clear_contenttypes():
    try:
        import django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'insb_port.settings')  # Replace with your project name
        django.setup()
        from django.contrib.contenttypes.models import ContentType
        ContentType.objects.all().delete()
        log("Cleared all ContentType entries.")
        return True
    except Exception as e:
        log(f"Error clearing content types: {e}")
        return False

def load_json_fixture():
    fixture_file = input("Enter the JSON filename to load (e.g. data.json): ")
    return run_command(f"python manage.py loaddata {fixture_file}")

def create_superuser():
    log("Creating Django superuser...")
    return run_command("python manage.py createsuperuser")

def run_dev_server():
    log("Starting development server at http://127.0.0.1:8000")
    return run_command("python manage.py runserver")

def main():
    state = load_state()

    if not state["venv_created"]:
        if not create_virtualenv(): return
        mark_done(state, "venv_created")

    if not state["venv_activated"]:
        if not activate_virtualenv(state): return

    if not state["requirements_installed"]:
        if not install_requirements(): return
        mark_done(state, "requirements_installed")

    if not state["env_updated"]:
        if not update_env_file(): return
        mark_done(state, "env_updated")

    if not state["migrated"]:
        if not run_migrations(): return
        mark_done(state, "migrated")

    if not state["contenttypes_cleared"]:
        if not clear_contenttypes(): return
        mark_done(state, "contenttypes_cleared")

    if not state["data_loaded"]:
        if not load_json_fixture(): return
        mark_done(state, "data_loaded")

    if not state["superuser_created"]:
        if not create_superuser(): return
        mark_done(state, "superuser_created")

    # if not state["server_started"]:
    #     if not run_dev_server(): return
    #     mark_done(state, "server_started")

    log("\nAll setup steps completed successfully!")
    cleanup_state_file()

if __name__ == "__main__":
    main()
