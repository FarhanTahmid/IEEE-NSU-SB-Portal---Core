"""
Django settings for insb_port project.

Generated by 'django-admin startproject' using Django 4.1.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from pathlib import Path
import os
# import dj_database_url
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/
from dotenv import load_dotenv
import os
load_dotenv()

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-*%*n1(qq^95t^+bl96wxty9h6qc4)h%ts27fv9egh8v0tj%60h'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

LOGIN_URL='/users/login'

# Application definition

INSTALLED_APPS = [
    
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'central_branch',
    'membership_development_team',
    'port',
    'users',
    'system_administration',
    'recruitment',
    'api',
    'logistics_and_operations_team',
    'events_and_management_team',
    'public_relation_team',
    'meeting_minutes',
    'main_website',
    'content_writing_and_publications_team'
]

MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'insb_port.urls'
import os
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'insb_port.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        
        # #********MYSQL SERVER ON LOCALHOST*********
        # 'ENGINE': 'django.db.backends.mysql',
        # 'NAME': 'insb_port',
        # 'USER': 'root',
        # 'PASSWORD': '',
        # 'HOST':'localhost',
        # 'PORT':'3306',
        # 'OPTIONS':{
        #     'init_command':"SET sql_mode='STRICT_TRANS_TABLES'"
        # }
        
        
        
        #DB.SQLITE3
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'

#TEMPLATE_DIRS=(os.path.join(os.path.dirname(__file__) ,'../Templates').replace('\\','/'))

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

#Date input Formats in the models
DATE_INPUT_FORMATS = ['%d-%m-%Y']


#static directory
STATIC_ROOT=os.path.join(BASE_DIR,'staticfiles')
STATICFIlES_DIRS=(os.path.join(BASE_DIR,'static'))
#Media Files
MEDIA_ROOT= os.path.join(BASE_DIR, 'User Files/')
MEDIA_URL= "/media_files/" 

#to do user login required
LOGIN_REDIRECT_URL='users:dashboard'
LOGOUT_REDIRECT_URL='users:logoutUser'
LOGIN_URL='users:login'


REST_FRAMEWORK={
    'DEFAULT_RENDERER_CLASSES':('rest_framework.renderers.JSONRenderer',)
}




#EMAIL SETTINGS
EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST='smtp.gmail.com'
EMAIL_PORT=587
EMAIL_HOST_USER=os.environ.get('email_user')
EMAIL_HOST_PASSWORD=os.environ.get('email_password')
EMAIL_USE_TLS=True