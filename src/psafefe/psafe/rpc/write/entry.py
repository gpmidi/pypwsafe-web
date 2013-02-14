#!/usr/bin/env python
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
""" RPC methods to create/update/delete entries within a psafe
Created on Aug 21, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
"""
import logging
log = logging.getLogger('psafefe.psafe.rpc.write.entry')

from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from psafefe.psafe.functions import getDatabasePasswordByUser
from psafefe.psafe.tasks.write import modifyEntries


@rpcmethod(
           name='psafe.write.entry.addUpdateDevice',
           signature=[
                      # Return value
                      'struct',
                      # Args
                      'string', 'string', 'int', 'int', 'string', 'struct',
                      ],
           )
@auth
def addUpdateDevice(username, password, repoID, safeID, deviceID, info, **kw):
    """
    info = {
            # Shell, SSH, console, etc logins
            'shellLogins':{'root':'bogus12345','sadm':'bogus12345'},
            # GUI/Web UI logins
            'guiLogins':{'root':'bogus12345','sadm':'bogus12345'},
            # Misc info
            'deviceInfo':{
                        'someKey':'someValue',
                        'ip':'1.2.3.4',
                        'class':'Production',
                        },
            }
    """
    try:
        repo = PasswordSafeRepo.objects.get(pk=repoID)
    except PasswordSafeRepo.DoesNotExist, e:
        log.warning("Got %r while trying to fetch Password Safe Repo %r", e, repoID)
        raise EntryDoesntExistError("No repo with an ID of %r" % repoID)
    if repo.user_can_access(user=kw['user'], mode="RW"):
        log.debug("User %r is ok to access %r", kw['user'], repo)
    else:
        log.warning("User %r is NOT allowed to access %r", kw['user'], repo)
        raise NoPermissionError("User %r can't access this repo" % kw['user'])
    try:
        safe = PasswordSafe.objects.get(pk=safeID)
    except PasswordSafe.DoesNotExist, e:
        log.warning("Got %r while trying to fetch Password Safe %r", e, safeID)
        raise EntryDoesntExistError("No safe with an ID of %r" % safeID)

    psafePassword = getDatabasePasswordByUser(kw['user'], password, safe, wait=True)

    actions = []

    if 'shellLogins' in info:
        for shellUser, shellPassword in info['shellLogins'].items():
            actions.append({
                            'action':'add-update',
                            'refilters':{},
                            'vfilters':{
                                        'Group':deviceID,
                                        'Username':shellUser,
                                        'Title':"Logins",
                                        },
                            'changes':{
                                       'Password':shellPassword,
                                       },
                            })
    if 'guiLogins' in info:
        for guiUser, guiPassword in info['guiLogins'].items():
            actions.append({
                            'action':'add-update',
                            'refilters':{},
                            'vfilters':{
                                        'Group':deviceID,
                                        'Username':guiUser,
                                        'Title':"GUI Logins",
                                        },
                            'changes':{
                                       'Password':guiPassword,
                                       },
                            })
    if 'deviceInfo' in info:
        for infoKey, infoValue in info['deviceInfo'].items():
            actions.append({
                            'action':'add-update',
                            'refilters':{},
                            'vfilters':{
                                        'Group':deviceID,
                                        'Username':infoKey,
                                        'Title':"Info",
                                        },
                            'changes':{
                                       'Password':infoValue,
                                       },
                            })

    res = modifyEntries.delay(# @UndefinedVariable
                              psafePK=safe.pk,
                              psafePassword=psafePassword,
                              actions=actions,
                              onError='fail',
                              )
    return res.wait()


