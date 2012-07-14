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
''' Read-only tasks for psafe interaction. 

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging
log = logging.getLogger(__name__)

from celery.decorators import task, periodic_task #@UnresolvedImport
from pypwsafe import PWSafe3, ispsafe3
import stat
from datetime import timedelta
import os, os.path
import psafefe.pws.pwcache

@task(ignore_result = False, expires = 24 * 60 * 60)
def addLoc(loc, passwords = []):
    """ Add a repo where psafes can be loaded. When used
    on an existing repo loc, it updates the cache. 
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @return: None
    """
    return psafefe.pws.pwcache.addLoc(loc = loc, passwords = passwords, passwordLookup = None)

@task(ignore_result = False, expires = 60 * 60)
def getSafeList(loc, passwords = []):
    """ Returns a list of psafes. Runs an cache update first.  
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @return: List of strings/filepaths
    """
    return psafefe.pws.pwcache.getSafeList(loc = loc, passwords = passwords)
    
@task(ignore_result = False, expires = 60 * 60)
def getSafe(loc, psafeLoc, passwords):
    """ Return a dict containing all psafe entries 
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/dir path
    @param psafeLoc: Full path to the psafe file to return. 
    @type psafeLoc: string/filepath 
    @param passwords: A list of zero or more passwords to use when decrypting safe. 
    @type passwords: List of strings           
    @return: dict
    """
    safe = psafefe.pws.pwcache.getSafe(loc = loc, psafeLoc = psafeLoc, passwords = passwords)
    if safe:
        ret = {}
        for entry in safe.getEntries():
            ret[str(entry.getUUID())] = entry.todict()
            log.debug("Added info for %r" % entry.getUUID())
            for k,v in ret[str(entry.getUUID())].items():
                log.debug("K: %r V: %r"%(k,v))
        return ret
    else:
        return {}
