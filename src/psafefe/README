# pws vs psafe
pws = Cache psafe objects via the local process's memory (Going to Deprecate)
psafe = Cache psafe objects using memory-only MySQL tables (Using going forward)


# Major TODO List
* Need to add an "on start" that will do an initial search for psafe files
** Goal: Have personal and non-personal pre-loaded
* Improve and validate input validation for all RPC functions
* Double check all permissions for repos and safes
** Put in unit tests for all possibilities
* Make a production-ready settings template and move the 
the test/debugging one over to a different settings file.
** Should also move test DB stuff to the database config
test settings. See link for test settings in the DB dict. 
**  https://docs.djangoproject.com/en/dev/ref/settings/#test-charset
* Consider moving psafe storage over to a storage manager
** https://docs.djangoproject.com/en/1.4/topics/files/
* Consider creating a new psafe repo for each user's personal psafe files
* Look into request timing differences in the RPC functions possibly giving 
away indications as to if the entry exists but the user doesn't have permissions.
* Move all logic out of individual RPC calls and into tasks or helper functions
** Should help prevent RPC vs View logic being different
* Update the Last Access Time for entries whenever the entry is accessed. 
* Make use of the 'extra' keyword argument for all logging calls.

# Helpful Sniplets

## Automatically create DB tables
If running tests (manage.py test), Django can/will change the DB to :memory: 
and auto create them. Assuming the DB engine is set to sqlite3. Should go in manage.py. 
http://docs.djangoproject.com/en/dev/howto/custom-management-commands/
http://stackoverflow.com/questions/3495964/in-django-how-do-i-call-the-subcommand-syncdb-from-the-initialization-script
    import sys, os
    if "shell" in sys.argv:
        os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
        from django.core.management import call_command
        call_command('syncdb', interactive = True)
        call_command('shell')
    else:
        execute_manager(settings)


# Logging Info

## Logging Extra Fields
Below are common fields that can be passed to logging functions using the extra
keyword argument. None are strictly required and keywords not listed can also be
used. 


### Semi-Required and/or Important
These fields are not required, but highly recommended when the field is relevant
to the code in question. 

#### user
Type: django.contrib.auth.models.User
Description: The user who initiated, requested, or is otherwise responsible for the code being executed. 

#### safePK
Type: int
Description: The PK of psafefe.psafe.models.PasswordSafe 


### Medium Priority Fields
These are fields that aren't commonly used but may be included. 

#### safes
Type: List of psafefe.psafe.models.PasswordSafe
Description: A list of all PasswordSafe objects relevant to the code block in question

#### memSafes
Type: List of psafefe.psafe.models.MemPSafe
Description: A list of psafefe.psafe.models.MemPSafe relevant to the calling code block. 

#### memSafe
Type: psafefe.psafe.models.MemPSafe
Description: A psafefe.psafe.models.MemPSafe relevant to the calling code block. 

#### memSafeEntry
Type: psafefe.psafe.models.MemPSafeEntry 
Description: A psafefe.psafe.models.MemPSafeEntry relevant to the calling code block. 

#### memSafeEntries
Type: List of psafefe.psafe.models.MemPSafeEntry 
Description: A list of psafefe.psafe.models.MemPSafeEntry relevant to the calling code block. 

#### memSafeEntryHistory
Type: psafefe.psafe.models.MemPasswordEntryHistory
Description: A psafefe.psafe.models.MemPasswordEntryHistory relevant to the calling code block. 

#### memSafeEntryHistoryList
Type: List of psafefe.psafe.models.MemPasswordEntryHistory
Description: A list of psafefe.psafe.models.MemPasswordEntryHistory relevant to the calling code block. 


### Low Priority Fields

#### memSafePK
Type: int
Description: The PK of the psafefe.psafe.models.MemPSafe that is relevant to the calling code block. 


### Fields That Should NOT Be Used

#### safeID
Type: int
Description: The PK of psafefe.psafe.models.PasswordSafe 

#### 
Type: 
Description: 
