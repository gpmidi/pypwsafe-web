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
def _filterComplex(username, password, safeIDs, include, exclude, **kw):
    """ 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param safeIDs: The PKs of all psafe objects that should be included in the search. 
    @type safeIDs: A list of ints
    @param include: A dict indicating what fields must match and possible values to match against.  
    @type include: A dict where keys are the fields names and the values are a list of possible values for matching entries.
    @param exclude: A dict indicating what fields/values must NOT match.   
    @type exclude: A dict where keys are the fields names and the values are a list of possible values for entries that should be excluded.
    @return: A list of dicts containing all matching entries
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise InvalidQueryError: One or more of the include/exclude field names or list of values is not valid.
    @note: Valid fields for filters: PK, UUID, Group, Title, Username, Notes, Password, Creation Time, Password Last Modification Time, Last Access Time, Password Expiry, Entry Last Modification Time, URL, AutoType, Run Command, Email.
    
    @warning: WHEN UPDATING THE ARG LIST OR THIS DOC STRING, MAKE SURE TO UPDATE THE RPC FUNCTIONS BELOW!  
    """
    extra = dict(username = username, safeIDs = safeIDs, user = kw['user'],)
    for safeID in safeIDs:
        if not isinstance(safeID, int):
            log.warn("The safeID/pk %r is not an int", safeID, extra = extra)
            raise InvalidQueryError("The safeID/pk %r is not an int" % safeID)

    if len(safeIDs) == 1:
        extra['safePK'] = safeID

    if not isinstance(safeIDs, list):
        log.warn("The list of safeIDs/safePKs is not a list. Got type %r, value %r. ", type(safeIDs), safeIDs, extra = extra)
        raise InvalidQueryError("The list of safeIDs/safePKs is not a list. Got %r." % type(safeIDs))

    safes = PasswordSafe.objects.filter(pk__in = safeIDs).select_related()

    # Let the user know which safeIDs couldn't be found.
    if len(safes) != len(safeIDs):
        log.warning("The list of PasswordSafe objects returned (%d) is a different length than the list of safeIDs (%d). ", len(safes), len(safeIDs), extra = extra)
        for safeID in safeIDs:
            if safes.filter(pk = safeID).count() == 0:
                raise EntryDoesntExistError("No safe with an ID of %r" % safeID)

    # Validate the user's access to all of the safes
    for safe in safes:
        if safe.repo.user_can_access(user = kw['user'], mode = "R"):
            log.debug("User %r is ok to access %r", kw['user'], safe.repo, extra = extra)
        else:
            log.warning("User %r is NOT allowed to access %r", kw['user'], safe.repo, extra = extra)
            # raise NoPermissionError("User %r can't access this repo" % kw['user'])
            raise EntryDoesntExistError("No safe with an ID of %r" % safeID)
        safes.append(safe)
    extra['safes'] = safes

    log.debug("User %r is querying %d safes", kw['user'], len(safes), extra = extra)

    # Get the cached entry or load it if needed
    memSafes = {}
    for safe in safes:
        psafePassword = getDatabasePasswordByUser(kw['user'], password, safe, wait = True)
        memSafes[safe.pk] = safe.getCached(canLoad = True, user = kw['user'], userPassword = password)

    extra['memSafes'] = memSafes
    if len(memSafes) == 1:
        extra['memSafePK'] = memSafes.keys()[0]

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
    entryFilter = MemPsafeEntry.objects.filter(safe__in = memSafes.values())
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


@rpcmethod(name = 'psafe.search.filterSafeComplex', signature = ['struct', 'string', 'string', 'int', 'struct', 'struct'])
@auth
def filterSafeComplex(username, password, safeID, include, exclude, **kw):
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
    @raise InvalidQueryError: One or more of the include/exclude field names or list of values is not valid.  
    @note: Valid fields: PK, UUID, Group, Title, Username, Notes, Password, Creation Time, Password Last Modification Time, Last Access Time, Password Expiry, Entry Last Modification Time, URL, AutoType, Run Command, Email.  
    """
    # Don't use **kwargs for the RPC args as rpc4django depends on the arg names being defined
    return _filterComplex(username = username, password = password, safeIDs = [safeID, ], include = include, exclude = exclude, **kw)


@rpcmethod(name = 'psafe.search.filterComplex', signature = ['struct', 'string', 'string', 'list', 'struct', 'struct'])
@auth
def filterComplex(username, password, safeIDs, include, exclude, **kw):
    """ 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param safeIDs: The PKs of all psafe objects that should be included in the search. 
    @type safeIDs: A list of ints
    @param include: A dict indicating what fields must match and possible values to match against.  
    @type include: A dict where keys are the fields names and the values are a list of possible values for matching entries.
    @param exclude: A dict indicating what fields/values must NOT match.   
    @type exclude: A dict where keys are the fields names and the values are a list of possible values for entries that should be excluded.
    @return: A list of dicts containing all matching entries
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise InvalidQueryError: One or more of the include/exclude field names or list of values is not valid.
    @note: Valid fields: PK, UUID, Group, Title, Username, Notes, Password, Creation Time, Password Last Modification Time, Last Access Time, Password Expiry, Entry Last Modification Time, URL, AutoType, Run Command, Email.  
    """
    # Don't use **kwargs for the RPC args as rpc4django depends on the arg names being defined
    return _filterComplex(username = username, password = password, safeIDs = safeIDs, include = include, exclude = exclude, **kw)
