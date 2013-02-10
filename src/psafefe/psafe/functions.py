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
''' Helper functions
Created on Aug 17, 2011

@author: gpmidi
'''
from django.contrib.auth.models import User, Group
from psafefe.psafe.models import *
from os.path import join
from django.conf import settings
import os
from psafefe.psafe.errors import *
from psafefe.psafe.rpc.errors import *

def getPersonalPsafeRepo():
    """ Returns the repo for the personal psafes """
    try:
        p = PasswordSafeRepo.objects.get(pk = settings.PSAFE_PERSONAL_PK)
    except PasswordSafeRepo.DoesNotExist:
        # TODO: Make the 'on dup key' error more user friendly
        p = PasswordSafeRepo(
                             pk = settings.PSAFE_PERSONAL_PK,
                             name = "Personal Password Safes",
                             path = settings.PSAFE_PERSONAL_PATH,
                             )
        p.save()
    return p

def getUsersPersonalSafe(user, userPassword, wait = True):
    """ Returns the user's personal psafe obj. 
    @warning: If wait=False, there is no guarantee that the mempsafe has been created and loaded. 
    """
    personalRepo = getPersonalPsafeRepo()
    name = "User_Password_Safe_%s.psafe3" % user.username
    try:
        psafe = PasswordSafe.objects.get(repo = personalRepo, filename = name, owner = user)
    except PasswordSafe.DoesNotExist, e:
        psafe = PasswordSafe(repo = personalRepo, filename = name, owner = user)
        psafe.save()
    except PasswordSafe.MultipleObjectsReturned, e:
        # TODO: Add in better handing of this
        raise RuntimeError("Found more than one personal psafe for user %r" % user)
    if not os.access(psafe.psafePath(), os.R_OK):
        # Create the safe
        from psafefe.psafe.tasks.write import newSafe
        task = newSafe.delay(# @UndefinedVariable
                          userPK = user.pk,
                          psafePK = psafe.pk,
                          psafePassword = userPassword,
                          dbName = "Personal Password Safe For %r" % user.username,
                          )
        if wait: 
            task.wait() 
    return psafe
    
def getDatabasePasswordByUser(user, userPassword, psafe, ppsafe = None, wait = True):
    """ Returns the password to decrypt psafe from the user's
    personal DB. Raise an error if the user doesn't have the
    password """
    if not ppsafe:
        ppsafe = getUsersPersonalSafe(user, userPassword, wait = wait)
    
    # Safety checks
    assert user.check_password(userPassword)
    assert ppsafe.owner == user
    assert psafe.repo.user_can_access(user = user, mode = "R")
    
    # work delayed 
    memsafe = MemPSafe.objects.get(safe = ppsafe)
    memsafe.onUse()
    ents = MemPsafeEntry.objects.filter(safe = memsafe)
    ents = ents.filter(group = "Password Safe Passwords.%d" % psafe.repo.pk)
    ents = ents.filter(title = "PSafe id %d" % psafe.pk)
    ents = ents.filter(username = psafe.filename)    
    
    # Use len so we cache results instead of count
    if len(ents) == 1:
        return ents[0].password
    elif len(ents) == 0:
        raise NoPasswordForPasswordSafe, "User %r doesn't have the password for safe %d" % (user, psafe.pk)
    else:
        raise ValueError, "Unexpected number of entries matched search for a psafe entries. Got %d results. " % len(ents)

def setDatabasePasswordByUser(user, userPassword, psafe, psafePassword, wait = True):
    """ Store/update the password for the given psafe in the user's personal psafe """
    repo = psafe.repo
    if not repo.user_can_access(user, mode = "R"):
        # User doesn't have access so it might as well not exist
        raise EntryDoesntExistError
    
    # User should have access to the requested safe
    ppsafe = getUsersPersonalSafe(user, userPassword)

    from psafefe.psafe.tasks import modifyEntries
    task = modifyEntries.delay(# @UndefinedVariable
                                psafePK = ppsafe.pk,
                                psafePassword = userPassword,
                                onError = "fail",
                                updateCache = True,
                                actions = [
                                           { 
                                            'action':'add-update',
                                            'refilters':{  },
                                            'vfilters':{
                                                        'Group':"Password Safe Passwords.%d" % psafe.repo.pk,
                                                        'Title':"PSafe id %d" % psafe.pk,
                                                        },
                                            'changes':{
                                                       'Group':"Password Safe Passwords.%d" % psafe.repo.pk,
                                                       'Title':"PSafe id %d" % psafe.pk,
                                                       'Username':psafe.filename,
                                                       'Password':psafePassword,
                                                       },
                                            'maxMatches': 5,
                                            },
                                           ],
                                )
    
    if wait:
        task.wait()

