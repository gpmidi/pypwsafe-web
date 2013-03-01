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


# Entry methods
@rpcmethod(name='psafe.read.getEntrysByGroup', signature=['struct', 'string', 'string', 'int', 'string'])
@auth
def getEntrysByGroup(username, password, safeID, groupName, **kw):
    """ Return a struct representing the requested entry from the cache. 
    @note: Will error out if not in the cache. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @return: A list containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    """
    try:
        safe = PasswordSafe.objects.get(pk=safeID)
    except PasswordSafe.DoesNotExist, e:
        log.warning("Got %r while trying to fetch Password Safe %r", e, safeID)
        raise EntryDoesntExistError("No safe with an ID of %r" % safeID)
    if safe.repo.user_can_access(user=kw['user'], mode="R"):
        log.debug("User %r is ok to access %r", kw['user'], safe.repo)
    else:
        log.warning("User %r is NOT allowed to access %r", kw['user'], safe.repo)
        # raise NoPermissionError("User %r can't access this repo" % kw['user'])
        raise EntryDoesntExistError

    psafePassword = getDatabasePasswordByUser(kw['user'], password, safe, wait=True)
    memSafe = safe.getCached(canLoad=True, user=kw['user'], userPassword=password)
    return [i.todict() for i in memSafe.mempsafeentry_set.filter(group=groupName)]


@rpcmethod(name='psafe.read.getEntryByPK', signature=['struct', 'string', 'string', 'int'])
@auth
def getEntryByPK(username, password, entPK, **kw):
    """ Return a struct representing the requested entry from the cache. 
    @note: Will error out if not in the cache. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The database id of the entry to return. 
    @type entPK: int
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    """
    try:
        ent = MemPsafeEntry.objects.get(pk=entPK)
        ent.onUse()
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError

    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode="R"):
        return ent.todict()

    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

@rpcmethod(name='psafe.read.getEntriesByUUID', signature=['array', 'string', 'string', 'string'])
@auth
def getEntriesByUUID(username, password, entUUID, **kw):
    """ Return a list of structs representing the requested entries, if any.  
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entUUID: UUID of the entry to pull as a dash separated string 
    @type entUUID: string    
    @return: A dictionary containing the entities properties
    @raise InvalidUUIDError: The UUID given isn't in a valid format or contains invalid chars. 
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it. 
    """
    try:
        uuid = UUID(entUUID)
    except:
        raise InvalidUUIDError, "%r is not a valid UUID" % entUUID

    found = []
    for ent in MemPsafeEntry.objects.filter(uuid=entUUID).select_related():
        ent.onUse()
        repo = ent.safe.safe.repo
        if repo.user_can_access(kw['user'], mode="R"):
            found.append(ent.todict())

    return found

@rpcmethod(name='psafe.read.getEntryByUUID', signature=['struct', 'string', 'string', 'string'])
@auth
def getEntryByUUID(username, password, entUUID, **kw):
    """ Return a struct representing the requested entry. Raises an error if more than
    one are found. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entUUID: UUID of the entry to pull as a dash separated string 
    @type entUUID: string    
    @return: A dictionary containing the entities properties
    @raise InvalidUUIDError: The UUID given isn't in a valid format or contains invalid chars. 
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise MultipleEntriesExistError: Found more than one entry with the given UUID.  
    """
    try:
        uuid = UUID(entUUID)
    except:
        raise InvalidUUIDError, "%r is not a valid UUID" % entUUID

    found = []
    for ent in MemPsafeEntry.objects.filter(uuid=entUUID):
        repo = ent.safe.safe.repo
        if repo.user_can_access(kw['user'], mode="R"):
            ent.onUse()
            found.append(ent.todict())

    if len(found) == 1:
        return found[0]
    elif len(found) == 0:
        raise EntryDoesntExistError("Cound't locate %r" % entUUID)
    raise MultipleEntriesExistError("Found %d entries for %r" % (len(found), entUUID))

#         Password Safe methods
@rpcmethod(name='psafe.read.getSafeByPK', signature=['struct', 'string', 'string', 'int'])
@auth
def getSafeByPK(username, password, entPK, **kw):
    """ Return a struct representing the requested psafe 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The database id of the safe to return. 
    @type entPK: int
    @return: A dict containing the properties of the requested safe. 
    """
    try:
        psafe = PasswordSafe.objects.get(pk=entPK)
    except PasswordSafe.DoesNotExist:
        raise EntryDoesntExistError

    ent = psafe.getCached(canLoad=True, user=kw['user'], userPassword=password)
    ent.onUse()
    repo = psafe.repo

    if repo.user_can_access(kw['user'], mode="R"):
        return ent.todict()

    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

@rpcmethod(name='psafe.read.getSafeByUUID', signature=['struct', 'string', 'string', 'string'])
@auth
def getSafeByUUID(username, password, entUUID, **kw):
    """ Return a struct representing the requested psafe 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The UUID of the safe to return. 
    @type entPK: string
    @return: A dict containing the properties of the requested safe. 
    """
    try:
        uuid = UUID(entUUID)
    except:
        raise InvalidUUIDError, "%r is not a valid UUID" % entUUID
    try:
        ents = PasswordSafe.objects.filter(uuid=entUUID)
    except PasswordSafe.DoesNotExist:
        raise EntryDoesntExistError

    found = []
    for ent in ents:
        ent.onUse()
        repo = ent.repo
        if repo.user_can_access(kw['user'], mode="R"):
            found.append(ent.getCached(
                                       canLoad=True,
                                       user=kw['user'],
                                       userPassword=password,
                                       ).todict())

    if len(found) == 1:
        return found[0]
    elif len(found) == 0:
        raise EntryDoesntExistError, "Cound't locate %r" % entUUID
    raise MultipleEntriesExistError, "Found %d entries for %r" % (len(found), entUUID)

@rpcmethod(name='psafe.read.getSafesByUUID', signature=['struct', 'string', 'string', 'string'])
@auth
def getSafesByUUID(username, password, entUUID, **kw):
    """ Return a list of structs representing the requested psafes 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's password
    @type password: string
    @param entPK: The UUID of the safe to return. 
    @type entPK: string
    @return: A list of dicts containing the properties of the requested safes. 
    """
    try:
        uuid = UUID(entUUID)
    except:
        raise InvalidUUIDError, "%r is not a valid UUID" % entUUID

    found = []
    for ent in PasswordSafe.objects.filter(uuid=entUUID):
        ent.onUse()
        repo = ent.repo
        if repo.user_can_access(kw['user'], mode="R"):
            memEnt = ent.getCached(canLoad=True, user=kw['user'], userPassword=password)
            found.append(memEnt.todict())

    return found

@rpcmethod(name='psafe.read.getSafesForUser', signature=['list', 'string', 'string'])
@auth
def getSafesForUser(username, password, getEntries=False, getEntryHistory=False, mode='R', **kw):
    """ Return a list of dicts representing all psafe files accessible by the requesting user. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's password
    @type password: string
    @param getEntries: If True, include all of the safe's password entries as well. 
    @type getEntries: boolean
    @param getEntryHistory: If True, return all of the old passwords for each password entry. 
    @type getEntryHistory: boolean
    @param mode: Limit safes to ones where the user has the given permissions. "R" for read, "RW" for read/write, and "A" for admin. 
    @type mode: string
    @return: A list of dicts representing all of the password safes the requesting user has access to.  
    """
    # TODO: Make this faster...this way is dumb
    valid = {}
    for repo in PasswordSafeRepo.objects.all():
        if repo.user_can_access(kw['user'], mode=mode):
            for safe in repo.passwordsafe_set.all():
                try:
                    safe.onUse()
                    valid[safe.pk] = safe.getCached(canLoad=True, user=kw['user'], userPassword=password)
                except Exception, e:
                    pass

    return [safe.todict(getEntries=getEntries, getEntryHistory=getEntryHistory) for safe in valid.values()]

