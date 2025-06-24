from datetime import datetime
import traceback

from system_administration.middleware import get_current_user
from system_administration.models import General_Log
from django.contrib.contenttypes.models import ContentType

from system_administration.system_error_handling import ErrorHandling


class System_Logs:
    
    def save_logs(instance, action):

        '''This function saves the general log whenever needed'''
        
        try:
            # Get current user using thread local storage
            user = get_current_user()

            log_details = {
                'action': action,
                'user': str(user) if user else "Anonymous",
            }
            
            #getting current time
            current_datetime = datetime.now()
            current_time = current_datetime.strftime('%d-%m-%Y %I:%M:%S %p')
            #getting the log
            if action == 'create':

                General_Log.objects.create(
                    log_of=instance,
                    log_details={current_time+"_0":log_details},
                )
            elif action == 'update' or action == 'delete':
                # Calculate update number (for tracking task updates)
                content_type = ContentType.objects.get_for_model(instance.__class__)

                log = General_Log.objects.filter(content_type=content_type, object_id=instance.pk)

                if not log:
                    General_Log.objects.create(log_of=instance, log_details={current_time+"_0":log_details})
                else:
                    log[0].update_number += 1
                    log[0].log_details[current_time+f"_{log[0].update_number}"] = log_details
                    log[0].save()
        
        except Exception as e:
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())