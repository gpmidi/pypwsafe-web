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
''' Psafe cache control
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from psafefe.psafe.tasks.load import loadSafe, findSafes
from psafefe.psafe.functions import getDatabasePasswordByUser

# Psafe sync methods
@rpcmethod(name = 'psafe.sync.updatePSafeCacheByPSafesPK', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def updatePSafeCacheByPSafesPK(username, password, entPKsUnsafe, sync, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. 
    @note: Any safes that the user doesn't have a valid password for will be skipped.
    @note: Any PKs to which a safe doesn't exist or the user lacks at least read-only perms will raise an EntryDoesntExistError.
    
    @warning: If sync is not set the count of successes will NOT include any errors that occur during sync. It will only include ones where the safe password lookup and object lookup succeeded.     
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPKs: A list of safe PKs that should have their cache updated.
    @type entPKs: list of ints
    @param sync: If True, wait for the safes to be updated before returning. 
    @type sync: boolean
    @return: If sync=False, the number of safes that have had a sync job successfully submitted. If sync=True, then the number of safes that had a sync job submitted andsuccessfullyy completed.  
    @raise NoPermissionError: User doesn't have password safe sync permissions
    """
    # Validate all safes and the users perms to them first
    ents = []
    for pk in list(entPKsUnsafe):
        try:
            ent = PasswordSafe.objects.get(pk = pk)
            ents.append(ent)
        except PasswordSafe.DoesNotExist:
            raise EntryDoesntExistError, "Couldn't find a PasswordSafe where pk=%r" % pk
        if not ent.repo.user_can_access(user = kw['user'], mode = "R"):
            raise EntryDoesntExistError, "Couldn't find a PasswordSafe where pk=%r" % pk
    sync = bool(sync)
    
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # user has perms
        waits = []
        successes = 0
        for psafe in ents:
            try:
                psafepass = getDatabasePasswordByUser(kw['user'], password, psafe)
                waits.append(loadSafe.delay(psafe_pk = entPK, password = psafepass))  # @UndefinedVariable
                successes += 1
            except:
                # TODO: Add some sort of logging for this
                pass
        # Doing sync, wait for all results
        if sync:
            for i in waits:
                try:
                    i.wait()
                except:
                    # TODO: Add some sort of logging for this
                    successes -= 1
        return successes
    raise NoPermissionError, "User can't sync psafes"

@rpcmethod(name = 'psafe.sync.updatePSafeCacheByPSafesByUUID', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def updatePSafeCacheByPSafesByUUID(username, password, entUUIDsUnsafe, sync, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. 
    @note: Any safes that the user doesn't have a valid password for will be skipped. 
    @note: If the user lacks perms to any psafe an EntryDoesntExistError will be raised
    @note: If one of the UUIDs doesn't exist, then an EntryDoesntExistError will be raised.
    @note: If the user has perms to multiple psafes with the same UUID and that UUID is listed, a MultipleEntriesExistError will be raised
    @warning: If sync is not set the count of successes will NOT include any errors that occur during sync. It will only include ones where the safe password lookup and object lookup succeeded.     
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entUUIDs: A list of safe UUIDs that should have their cache updated.
    @type entUUIDs: list of strings
    @param sync: If True, wait for the safes to be updated before returning. 
    @type sync: boolean
    @return: The number of safes successfully updated
    @raise NoPermissionError: User doesn't have password safe sync permissions
    @raise EntryDoesntExistError: No psafe with the request UUID exists that the user as atleast read-only access to. 
    @raise MultipleEntriesExistError: More than one psafe with the given UUID was found. 
    """    
    # Validate input type    
    entUUIDs = []
    for pk in list(entUUIDsUnsafe):
        entUUIDs.append(str(pk))
    sync = bool(sync)

    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # user has perms
        # Validate all safes BEFORE we start calling loadSafe
        validSafes = []
        for entUUID in entUUIDs:
            psafes = PasswordSafe.objects.filter(uuid = entUUID)
            # Validate perms
            okPSafes = []
            for ent in psafes:
                if ent.repo.user_can_access(user = kw['user'], mode = "R"):
                    okPSafes.append(ent) 
            # Only allow one UUID
            if len(psafes) > 1:
                raise MultipleEntriesExistError, "%r safes with a UUID of %r were found" % (psafes.count(), entUUID)
            elif len(psafes) == 0:
                raise EntryDoesntExistError, "Couldn't find a PasswordSafe where uuid=%r" % entUUID
            validSafes.append(psafes[0])
        # All safes found are valid, so start the loadSafes
        waits = []
        successes = 0
        for psafe in validSafes:
            try:
                psafepass = getDatabasePasswordByUser(kw['user'], password, psafe)
                waits.append(loadSafe.delay(psafe_pk = entPK, password = psafepass))  # @UndefinedVariable
                successes += 1
            except:
                # TODO: Add some sort of logging for this
                pass
        # Doing sync, wait for all results and watch for errors
        if sync:
            for i in waits:
                try:
                    i.wait()
                except:
                    # TODO: Add some sort of logging for this
                    successes -= 1
        return successes
    else:
        raise NoPermissionError, "User can't sync psafes"

@rpcmethod(name = 'psafe.sync.searchForNewPSafeFiles', signature = ['boolean', 'string', 'string', 'boolean'])
@auth
def searchForNewPSafeFiles(username, password, sync, **kw):
    """ Search all repos for NEW psafes. Will not reload existing safes.
    
    @return: True on success, false otherwise
    @raise NoPermissionError: User lacks password sync perms 
    """
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # Limit to repos the user has at least read-only access to
        # Only do if the user has sync perms as this may take a while 
        repos = []
        for repo in PasswordSafeRepo.objects.all():
            if repo.user_can_access(user = kw['user'], mode = "R"):
                repos.append(repo.pk)
        res = findSafes.delay(repoByPK = repos)  # @UndefinedVariable
        try:
            if sync:
                safesFound = res.wait()
        except:
            # TODO: Add some sort of logging for this
            return False
        return True
    raise NoPermissionError, "User can't sync psafes"

@rpcmethod(name = 'psafe.sync.searchForNewPSafeFiles', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def searchForNewPSafeFilesByRepoPK(username, password, repoByPK, sync, **kw):
    """ Search the given repos for NEW psafes. Will not reload existing safes.
    @param repoByPK: A list of repo PKs to check for new safes
    @type repoByPK: array of ints  
    @return: True on success, false otherwise
    @raise NoPermissionError: User lacks password sync perms
    @raise EntryDoesntExistError: One of the repo PKs doesn't exist or the user lacks at least read-only perms to the safe. 
    """
    repos = []
    for repoPK in repoByPK:
        # Make sure it exists and the user has access
        try:
            repo = PasswordSafeRepo.objects.get(pk = repoPK)
        except PasswordSafeRepo.DoesNotExist:
            raise EntryDoesntExistError, "Couldn't find a PasswordSafeRepo where PK=%r" % repoPK
        if repo.user_can_access(user = kw['user'], mode = "R"):
            raise EntryDoesntExistError, "Couldn't find a PasswordSafeRepo where PK=%r" % repoPK
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        res = findSafes.delay()  # @UndefinedVariable
        try:
            if sync:
                safesFound = res.wait()
        except:
            # TODO: Add some sort of logging for this
            return False
        return True
    raise NoPermissionError, "User can't sync psafes"




