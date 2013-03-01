#===============================================================================
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
#===============================================================================
''' Read-only functions
Created on Aug 16, 2011

@author: gpmidi
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from uuid import UUID
from django.conf import settings
from psafefe.psafe.functions import getDatabasePasswordByUser
import datetime
import sys

FILTER_FIELDS_MAPPING = {
                         'PK':(int, 'pk'),
                         'UUID':(UUID, 'uuid'),
                         'Group':(str, 'group'),
                         'Title':(str, 'title'),
                         'Username':(str, 'username'),
                         'Notes':(str, 'notes'),
                         'Password':(str, 'password'),
                         'Creation Time':(datetime.datetime, 'creationTime'),
                         'Password Last Modification Time':(datetime.datetime, 'passwordModTime'),
                         'Last Access Time':(datetime.datetime, 'accessTime'),
                         'Password Expiry':(datetime.datetime, 'passwordExpiryTime'),
                         'Entry Last Modification Time':(datetime.datetime, 'modTime'),
                         'URL':(str, 'url'),
                         'AutoType':(str, 'autotype'),
                         'Run Command':(str, 'runCommand'),
                         'Email':(str, 'email'),
                         'Old Passwords':(str, None),
                         }

# Entry methods
@rpcmethod(name = 'psafe.search.filterComplex', signature = ['struct', 'string', 'int', 'struct', 'struct'])
@auth
def filterComplex(username, password, safeID, include, exclude, **kw):
    """ 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param safeID: The PK of the PasswordSafe object
    @type safeID: int
    @param include: A dict indicating what fields must match and possible values to match against.  
    @type include: A dict where keys are the fields names and the values are a list of possible values for matching entries.
    @param exclude: A dict indicating what fields/values must NOT match.   
    @type exclude: A dict where keys are the fields names and the values are a list of possible values for entries that should be excluded.
    @return: A list of dicts containing all matching entries
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @note: Valid fields: PK, UUID, Group, Title, Username, Notes, Password, Creation Time, Password Last Modification Time, Last Access Time, Password Expiry, Entry Last Modification Time, URL, AutoType, Run Command, Email.  
    """
    extra = dict(username = username, safeID = safeID)
    try:
        safe = PasswordSafe.objects.get(pk = safeID)
    except PasswordSafe.DoesNotExist, e:
        log.warning("Got %r while trying to fetch Password Safe %r", e, safeID, extra = extra)
        raise EntryDoesntExistError("No safe with an ID of %r" % safeID)
    if safe.repo.user_can_access(user = kw['user'], mode = "R"):
        log.debug("User %r is ok to access %r", kw['user'], safe.repo, extra = extra)
    else:
        log.warning("User %r is NOT allowed to access %r", kw['user'], safe.repo, extra = extra)
        # raise NoPermissionError("User %r can't access this repo" % kw['user'])
        raise EntryDoesntExistError("No safe with an ID of %r" % safeID)

    # Get the cached entry or load it if needed
    psafePassword = getDatabasePasswordByUser(kw['user'], password, safe, wait = True)
    memSafe = safe.getCached(canLoad = True, user = kw['user'], userPassword = password)
    extra['memSafePK'] = memSafe.pk

    # Provide basic validation of the filters since the DB filter errors aren't passed on to the user
    for filterName, filterDict in [ ('include', include), ('exclude', exclude), ]:
        for field, values in filterDict.items():
            if field not in FILTER_FIELDS_MAPPING:
                log.warning("User %r passed in field %r which isn't valid", kw['user'], field, extra = extra)
                raise InvalidQueryError("The field %r:%r in %r is not a valid field name" % (field, values, filterName))
            if not isinstance(values, list):
                log.warning("User %r passed in a value of %r for field %r. The value needs to be a list. ", kw['user'], values, field, extra = extra)
                raise InvalidQueryError("The value list for field %r, which is %r, is not a list" % (field, values))
            fieldType, modelFieldName = FILTER_FIELDS_MAPPING[field]
            for value in values:
                if not isinstance(value, fieldType):
                    log.warning("User %r passed in value %r for field %r which isn't %r", kw['user'], value, fieldType, extra = extra)
                    raise InvalidQueryError("The value %r from field %r in filter %r is not of type %r" % (value, field, filterName, fieldType))
    # Passed sanity checks of data...now to build the query
    entryFilter = MemPsafeEntry.objects.filter(safe = memSafe)
    try:
        for field, values in include.items():
            if field == 'Old Passwords':
                for value in values:
                    entryFilter = entryFilter.filter(mempasswordentryhistory__contains = value)
            else:
                fieldFilterName = "%s__in" % field
                entryFilter = entryFilter.filter(**{fieldFilterName:values})
    except Exception, e:
        log.warn("Error processing include filter: %r User: %r", e, kw['user'], exc_info = sys.exc_info(), extra = extra)
        raise InvalidQueryError("Error in include filter")

    try:
        for field, values in exclude.items():
            if field == 'Old Passwords':
                for value in values:
                    entryFilter = entryFilter.exclude(mempasswordentryhistory__contains = value)
            else:
                fieldFilterName = "%s__in" % field
                entryFilter = entryFilter.exclude(**{fieldFilterName:values})
    except Exception, e:
        log.warn("Error processing exclude filter: %r User: %r", e, kw['user'], exc_info = sys.exc_info(), extra = extra)
        raise InvalidQueryError("Error in exclude filter")

    # Turn objects to a list of dicts
    ret = [i.todict() for i in entryFilter.select_related()]
    log.debug("User %r's query returned %d entries", kw['user'], len(ret), extra = extra)
    return ret


