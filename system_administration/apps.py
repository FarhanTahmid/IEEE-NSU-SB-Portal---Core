from django.apps import AppConfig

class SystemAdministrationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'system_administration'

    def ready(self):
        import system_administration.signals

