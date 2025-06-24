import sys
import traceback
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from system_administration.system_error_handling import ErrorHandling
from system_administration.system_logs import System_Logs

# Models to exclude from logging
EXCLUDED_MODELS = ['General_Log', 'ContentType', 'Task_Log','Migration', 'Permission', 'SystemErrors', 'Session', 'LogEntry', 'adminUsers']
# List of app labels to exclude (default Django apps)
EXCLUDED_APP_LABELS = [
    'admin',
    'auth',
    'contenttypes',
    'sessions',
    'messages',
]

def is_migration_running():
    """Check if the command being run is a migration."""
    return 'makemigrations' in sys.argv or 'migrate' in sys.argv or 'loaddata' in sys.argv

def create_general_log(instance, action):
    # Check if model should be excluded from logging
    try:
        if is_migration_running():
            return
        
        if instance.__class__.__name__ in EXCLUDED_MODELS:
            return
        
        System_Logs.save_logs(instance, action)
                    
    except Exception as e:
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())

def should_log_model(sender):
    """Determine if the model should be logged based on certain criteria"""

    return (
        sender.__name__ not in EXCLUDED_MODELS and
        sender._meta.app_label not in EXCLUDED_APP_LABELS
    )

@receiver(post_save)
def log_create_or_update(sender, instance, created, **kwargs):
    if should_log_model(sender):
        create_general_log(instance, 'create' if created else 'update')

@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    if should_log_model(sender):
        create_general_log(instance, 'delete')