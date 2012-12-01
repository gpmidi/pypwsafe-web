# !/usr/bin/env python
# ===============================================================================
# This file is part of PyPWSafe.
# 
#    PyPWSafe is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
# 
#    PyPWSafe is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#    You should have received a copy of the GNU General Public License
#    along with PyPWSafe.  If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.html 
# ===============================================================================
""" Django settings for psafefe project.
@warning: The settings below are for TESTING ONLY. Do NOT use them in production. 
FIXME: Provide a template for production settings modules. 
"""
DEBUG = True
TEMPLATE_DEBUG = DEBUG

import sys, os, os.path
import datetime

#            Dajax/Dajaxice
DAJAXICE_MEDIA_PREFIX = 'dajax'

import djcelery
djcelery.setup_loader()

#            Django
ADMINS = (
    # ('Your Name', 'your_email@example.com'),
    # (Optional) Send error emails to root on the local machine. Let the system forward them to whomever, if desired. 
    ("An Admin", "root@localhost"),
)

MANAGERS = ADMINS

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        # Change by day for the moment
        'NAME': '/tmp/database.psafe3',  # Or path to database file if using sqlite3.
        'USER': '',  # Not used with sqlite3.
        'PASSWORD': '',  # Not used with sqlite3.
        'HOST': '',  # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',  # Set to empty string for default. Not used with sqlite3.
        'OPTIONS': {
                    # Use for MySQL DB
                    # 'init_command': 'SET storage_engine=INNODB',
                    # 'autocommit': True,
        },
    },
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/New_York'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = '../../media/'

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = '/media/'

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = '../../static/'

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
ADMIN_MEDIA_PREFIX = '/static/admin/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

DEFAULT_FILE_STORAGE = "../../files"

# Make this unique, and don't share it with anybody.
SECRET_KEY = 's2&ewc3gnwv$u4n#)x=jtm^3%%2*wkouiv6vaaaesm8q2_e#23'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

ROOT_URLCONF = 'psafefe.urls'

TEMPLATE_CONTEXT_PROCESSORS = (
                            "django.core.context_processors.auth",
                            "django.core.context_processors.debug",
                            "django.core.context_processors.i18n",
                            "django.core.context_processors.media",
                            'django.contrib.messages.context_processors.messages',
                            'django.core.context_processors.request',
                            'django.core.context_processors.static',
                            )

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    '../../templates/'
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 60 * 60 * 24,
        'OPTIONS': {
            'MAX_ENTRIES': 100000
        },
    }
}

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'django.contrib.comments',
    'django.contrib.admin',
    # Handy AJAX tools
    'dajaxice',
    'dajax',
    # Async task exectuion
    'djcelery',
    # Provide easy XML-RPC and JSON-RPC
    'rpc4django',
    # Our code
    'psafefe.pws',
    'psafefe.psafe',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
#        'mail_admins': {
#            'level': 'ERROR',
#            'class': 'django.utils.log.AdminEmailHandler'
#        },
#        'file': {
#            'level': 'DEBUG',
#            'class': 'logging.FileHandler',
#            'filename': '/tmp/debug.log',
#        },
        'console':{
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'stream': sys.stdout,
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}

#            Celery settings
BROKER_HOST = "localhost"
BROKER_PORT = 5672
BROKER_USER = "gpdev"
BROKER_PASSWORD = "bogus12345"
BROKER_VHOST = "gpdev"
CELERY_RESULT_BACKEND = "amqp"
# Remove any task results after an hour. High volume sites may need to reduce this. 
TASK_RESULT_EXPIRES = 1 * 60 * 60
# Use Celery's test runner so that we can do unit tests involving it
TEST_RUNNER = 'djcelery.contrib.test_runner.CeleryTestSuiteRunner'
# Don't bother with the daemon
# TODO: Make sure to remove this for anything that isn't for running tests
CELERY_ALWAYS_EAGER = True

#            RPC4Django
# Set these to true in high security env
RPC4DJANGO_RESTRICT_RPCTEST = False
RPC4DJANGO_RESTRICT_INTROSPECTION = False
# Extra logging for debugging - Disable in production
RPC4DJANGO_LOG_REQUESTS_RESPONSES = True

#             PSAFE Settings

# Where a user's private psafe is stored. These safes allow a user to save
# the passwords to other safes in a safe encrypted with their own password. 
# @note: The INITIAL location - If you need to change the location after it's
# been created in the DB, then update the DB entry. Best practice would be to change
# it in here too. 
PSAFE_PERSONAL_PATH = "psafes_personal"

# The PK of the personal psafe entry in PasswordSafeRepo
PSAFE_PERSONAL_PK = 1

# The max number of psafes to return in a single RPC call that does NOT 
# also return all entries in the psafe. 
PSAFE_RPC_MAX_SAFES = 16 * 1024

# The max number of psafes to return in a single RPC call that  
# also returns all entries in the psafe. 
PSAFE_RPC_MAX_SAFES_RCR = 1024



