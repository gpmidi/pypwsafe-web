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
''' Psafe read related functions. 

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging
log = logging.getLogger(__name__)

from rpc4django import rpcmethod
from xmlrpclib import Binary
from psafefe.pws.rpc.errors import *
from psafefe.pws.rpc.auth import auth
from psafefe.pws.models import *
from psafefe.pws.tasks.device import *
from uuid import uuid4

@rpcmethod(name = 'psafefe.pws.read.getInfoByUUID', signature = ['struct', 'string', 'string', 'int', 'int', 'string', 'array'])
@auth
def getInfoByUUID(username, password, locID, safeID, entryUUID, passwords, **kw):
    """ Return a struct representing the requested entries
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry to return
    @type safeID: int
    @param entryUUID: UUID of the entry in string form, with dashes. 
    @type entryUUID: string  
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found.
    @note: The repo.updatePSafeList function may need to be run prior to using this function. The DB-based list of psafes and loc must exist and be up-to-date.   
    """
    try:
        loc = PasswordSafeRepo.objects.get(pk = locID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, locID))
        raise InvalidIDError, "PK %r not found in repo list" % locID
    if not loc.user_can_access(user = kw['user'], mode = 'R'):
        raise NoPermissionError, "%r doens't have read-only access to the given loc" % username
    try:
        safe = PasswordSafe.objects.get(pk = safeID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, safeID))
        raise InvalidIDError, "PK %r not found in psafe list" % safeID
    
    # Now know the user should have access to it and that it's already known
    r = lookupByUUID.delay(loc = loc.path, uuid = entryUUID, psafeLoc = safe.filename, passwords = passwords)
    log.debug("Ran %r" % r)
    return r.wait()
    
@rpcmethod(name = 'psafefe.pws.read.getInfoListByDevice', signature = ['struct', 'string', 'string', 'int', 'int', 'string', 'array'])
@auth
def getInfoListByDevice(username, password, locID, safeID, device, passwords, **kw):
    """ Return struct representing the requested entries 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry to return
    @type safeID: int
    @param device: Device FQDN
    @type device: string/hostname
    @param passwords: A list of passwords to use when decrypting psafes. 
    @type passwords: list of strings   
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found.
    @note: The repo.updatePSafeList function may need to be run prior to using this function. The DB-based list of psafes and loc must exist and be up-to-date.  
    """
    try:
        loc = PasswordSafeRepo.objects.get(pk = locID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, locID))
        raise InvalidIDError, "PK %r not found in repo list" % locID
    if not loc.user_can_access(user = kw['user'], mode = 'R'):
        raise NoPermissionError, "%r doens't have read-only access to the given loc" % username
    try:
        safe = PasswordSafe.objects.get(pk = safeID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, safeID))
        raise InvalidIDError, "PK %r not found in psafe list" % safeID
    
    # Now know the user should have access to it and that it's already known
    r = lookupByDevice.delay(loc = loc.path, device = device, psafeLoc = safe.filename, passwords = passwords)
    log.debug("Ran %r" % r)
    return r.wait()

@rpcmethod(name = 'psafefe.pws.read.getInfoByDevice', signature = ['struct', 'string', 'string', 'int', 'int', 'string', 'array'])
@auth
def getInfoByDevice(username, password, locID, safeID, device, passwords, **kw):
    """ Return struct representing the requested entry. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry to return
    @type safeID: int
    @param device: Device FQDN
    @type device: string/hostname
    @param passwords: A list of passwords to use when decrypting psafes. 
    @type passwords: list of strings   
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found.
    @note: The repo.updatePSafeList function may need to be run prior to using this function. The DB-based list of psafes and loc must exist and be up-to-date.  
    """
    try:
        loc = PasswordSafeRepo.objects.get(pk = locID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, locID))
        raise InvalidIDError, "PK %r not found in repo list" % locID
    if not loc.user_can_access(user = kw['user'], mode = 'R'):
        raise NoPermissionError, "%r doens't have read-only access to the given loc" % username
    try:
        safe = PasswordSafe.objects.get(pk = safeID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, safeID))
        raise InvalidIDError, "PK %r not found in psafe list" % safeID
    
    # Now know the user should have access to it and that it's already known
    r = lookupByDevice.delay(loc = loc.path, device = device, psafeLoc = safe.filename, passwords = passwords)
    log.debug("Ran %r" % r)
    infos = r.wait()
    
    ret = dict(Logins = {}, Info = {}, Other = {})
    for uuid, entry in infos.items():
        if entry.has_key('Group'):
            ret['Group'] = entry['Group']
        if entry.has_key("Title"):
            if entry['Title'] == 'Logins' or entry['Title'] == 'Login':
                log.debug("Found a login entry: %r" % entry)
                ret['Logins'][entry['Username']] = entry['Password']
                continue
            elif entry['Title'] == 'Info':
                log.debug("Found an Info entry: %r" % entry)
                if entry['Password'] == "See Note" and entry.has_key('Note'):
                    ret['Info'][entry['Username']] = entry['Note']
                else:
                    ret['Info'][entry['Username']] = entry['Password']
                continue
        log.debug("Found an unknown entry: %r" % entry)
        if entry['Password'] == "See Note" and entry.has_key('Note'):
            ret['Other'][entry['Username']] = entry['Note']
        else:
            ret['Other'][entry['Username']] = entry['Password']
    
    if kw['request'].META['CONTENT_TYPE']=='text/xml':
        for u,p in ret['Logins'].items():
            ret['Logins'][u]=Binary(p)
        for k,v in ret['Info'].items():
            ret['Info'][k]=Binary(v)
        for k,v in ret['Other'].items():
            ret['Other'][k]=Binary(v)

    return ret
