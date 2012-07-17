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
''' Psafe write related functions. 

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging
log = logging.getLogger(__name__)

from rpc4django import rpcmethod
from psafefe.pws.rpc.errors import *
from psafefe.pws.rpc.auth import auth
from psafefe.pws.models import *
from psafefe.pws.tasks.device import *
import psafefe.pws.tasks.write
from uuid import uuid4

@rpcmethod(name = 'psafefe.pws.write.addUpdateDevice', signature = ['struct', 'string', 'string', 'int', 'int', 'string', 'array', 'struct', 'struct'])
@auth
def addUpdateDevice(username, password, locID, safeID, device, passwords, entryLogins = {}, entryInfo = {}, **kw):
    """ Add/update info for the given device. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry to return
    @type safeID: int
    @param device: Name of the device to add/update info for
    @type device: string/hostname
    @param passwords: A list of passwords to use when decrypting psafes. 
    @type passwords: list of strings  
    @param entryLogins: A key/value mapping of logins for the host. k=username v=password
    @type entryLogins: dict
    @param entryInfo: A key/value mapping of useful info for the device
    @type entryInfo: dict 
    @return: None
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found.   
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
    r = psafefe.pws.tasks.write.addUpdateDevice.delay(device = device, loc = loc.path, psafeLoc = safe.filename, logins = entryLogins, info = entryInfo, passwords = passwords)
    log.debug("Ran %r" % r)
    return r.wait()
    
@rpcmethod(name = 'psafefe.pws.write.addUpdateByUUID', signature = ['struct', 'string', 'string', 'int', 'int', 'string', 'array', 'struct'])
@auth
def addUpdateByUUID(username, password, locID, safeID, uuid, passwords, entryInfo = {}, **kw):
    """ Add/update info for the given entry uuid. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry to return
    @type safeID: int
    @param device: Name of the device to add/update info for
    @type device: string/hostname
    @param passwords: A list of passwords to use when decrypting psafes. 
    @type passwords: list of strings  
    @param entryInfo: A key/value mapping info for the entry properties. 
    @type entryInfo: dict
    @return: None
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found.   
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
    r = psafefe.pws.tasks.write.addUpdateByUUID.delay(uuid = uuid, loc = loc.path, psafeLoc = safe.filename, info = entryInfo, passwords = passwords)
    log.debug("Ran %r" % r)
    return r.wait()
    
