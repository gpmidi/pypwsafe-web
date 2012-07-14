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
''' Psafe repo related functions. 

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
from psafefe.pws.tasks.safe import *
from uuid import uuid4

@rpcmethod(name = 'psafefe.pws.repo.updatePSafeList', signature = ['struct', 'string', 'string', 'int', 'array'])
@auth
def updatePSafeList(username, password, locID, passwords, **kw):
    """ Updates the DB-based list of known psafe files in 
    the given repo. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @return: A dictionary containing the psafes found
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
    r = getSafeList.delay(loc = loc.path, passwords = passwords)
    log.debug("Got %r" % r)
    ret = {}
    for safe in r.wait():
        safe = str(safe)
        ret[safe] = getSafe.delay(loc = loc.path, psafeLoc = safe, passwords = passwords)
        try:
            s = PasswordSafe.objects.get(repo = loc, filename = safe)
            log.debug("Found %r" % s)
        except PasswordSafe.DoesNotExist, e:
            s = PasswordSafe(repo = loc, filename = safe, owner = None)
            s.save()
            log.debug("Created %r" % s)
    # Wait for safe fetches
    for safe, info in ret.items():
        ret[safe] = info.wait()
        for entryUUID, nfo in ret[safe].items():
            for k, v in nfo.items():
                if type(v) == type(''):
                    nfo[k] = Binary(v)
    return ret

@rpcmethod(name = 'psafefe.pws.repo.updatePSafeOwner', signature = ['int', 'string', 'string', 'int', 'int', 'array'])
@auth
def updatePSafeOwner(username, password, locID, safeID, passwords, **kw):
    """ Updates the DB-based list psafe entry such that the
    calling user is recorded as the owner. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param locID: PK of the psafe repo to use
    @type locID: int
    @param safeID: PK of the entry update
    @type safeID: int
    @param passwords: A list of passwords to use when decrypting psafes. 
    @type passwords: list of strings 
    @return: PK of the psafe
    @raise NoPermissionError: The user doesn't have enough perms to access the given loc
    @raise InvalidIDError: The PK passed in wasn't found. 
    """
    try:
        loc = PasswordSafeRepo.objects.get(pk = locID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, locID))
        raise InvalidIDError, "PK %r not found in repo list" % locID
    if not loc.user_can_access(user = kw['user'], mode = 'RW'):
        raise NoPermissionError, "%r doens't have read/write access to the given loc" % username
    try:
        safe = PasswordSafe.objects.get(pk = safeID)
    except Exception, e:
        log.debug("Got %r trying to lookup pk=%r" % (e, safeID))
        raise InvalidIDError, "PK %r not found in psafe list" % safeID
    
    # Make sure the user knows the pw to the safe
    s = getSafe.delay(loc = loc.path, psafeLoc = safe.filename, passwords = passwords)
    s = s.wait()
    log.debug("Got %r for %r's info" % (s, safe))
    if len(s) == 0:        
        raise BadUsernamePasswordError, "Psafe passwords %r couldn't decrypt given safe" % passwords          
    
    safe.owner = kw['user']
    safe.save()
    
    log.debug("Updated %r's owner to %r" % (safe, kw['user']))
    return safe.pk
    
    
    
    
