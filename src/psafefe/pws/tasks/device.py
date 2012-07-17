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
import re

@task(ignore_result = False, expires = 60 * 60)
def lookupByUUID(loc, uuid, psafeLoc, passwords = []):
    """ Add a repo where psafes can be loaded 
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @param uuid: The UUID of the entry to return. Must be in dash-seperated string format.
    @type uuid: string/uuid
    @param psafeLoc: Full path to the psafe file to return.   
    @type psafeLoc: string/filepath 
    @return: A dict of entry properities or None if no such entry exists. 
    """
    from safe import getSafe
    safe = getSafe(loc = loc, psafeLoc = psafeLoc, passwords = passwords)
    if safe.has_key(uuid):
        return safe[uuid]
    else:
        return None
    
@task(ignore_result = False, expires = 60 * 60)
def lookupByInfo(loc, psafeLoc, passwords = [], title = None, group = None, username = None):
    """ Add a repo where psafes can be loaded 
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @param psafeLoc: Full path to the psafe file to return.   
    @type psafeLoc: string/filepath 
    @param title: A regex in string form that the title must match. None to match everything. 
    @type title: string/regex
    @param group: A regex in string form that the group must match. None to match everything. 
    @type group: string/regex
    @param username: A regex in string form that the username must match. None to match everything. 
    @type username: string/regex
    @return: A list of dicts of entry properties or None if no such entry exists.
    @note: If none of the selectors are given, then all entries in the safe are returned.  
    """
    from safe import getSafe
    safe = getSafe(loc = loc, psafeLoc = psafeLoc, passwords = passwords)
    if title:
        title = re.compile(title)
    if group:
        group = re.compile(group)
    if username:
        username = re.compile(username)
    for uuid, entry in safe.items():
        match = True
        if title:
            match = match and title.match(entry['Title'])
        if group:
            match = match and title.match(entry['Group'])
        if username:
            match = match and title.match(entry['UsernameRecordProp'])
        if match:
            log.debug("Entry %r matches. Keeping. " % uuid)
        else:
            log.debug("Removing entry %r from found list" % uuid)
            del safe[uuid]
    return safe
    
@task(ignore_result = False, expires = 60 * 60)
def lookupByDevice(device, loc, psafeLoc, passwords = []):
    """ Find all entries associated with the given device. 
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @param psafeLoc: Full path to the psafe file to return.   
    @type psafeLoc: string/filepath 
    @param device: The hostname of the device to find entrie(s) for. 
    @type device: string/hostname
    @return: A list of dicts of entry properties or None if no such entry exists.  
    """
    from safe import getSafe
    safe = getSafe(loc = loc, psafeLoc = psafeLoc, passwords = passwords)
    
    s = device.split('/')
    device_full = s[-1].split('.')
    device_host = device_full[0]
    
    group_match = '.'.join(s[:-1]+[device_host,])
    
    for uuid, entry in safe.items():
        if entry.has_key('Group'):
            log.debug("Checking if %r matches %r" % (entry['Group'], group_match))
            if group_match == entry['Group']:
                log.debug("%r is in the right group" % uuid)
            else:
                log.debug("%r not it" % uuid)
                del safe[uuid]
        else:
            log.debug("%r not it" % uuid)
            del safe[uuid]
    return safe
