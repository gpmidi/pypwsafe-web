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
''' Write tasks for psafe interaction. 

@author: Paulson McIntyre <paul@gpmidi.net>

Common props(aka keys) for info args: 
    - Port: Management port to connect to
    - Proto: SSH or other protocol to use for management access. 
    - Default Login: The primary username to use when picking from the logins.
    - Compress: True or False indicating if the connection should be compressed. Doesn't apply to all protos.  
    - SSHPrvKey: A newline separated list of SSH private keys to auth with.  
    - Host: The hostname/IP to use when connecting to manage the device.  
'''
import logging
log = logging.getLogger(__name__)

from celery.decorators import task, periodic_task #@UnresolvedImport
from pypwsafe import PWSafe3, ispsafe3, Record
import stat
from datetime import timedelta
import os, os.path
from uuid import uuid4

@task(ignore_result = False, expires = 24 * 60 * 60)
def addUpdateDevice(device, loc, psafeLoc, logins = {}, info = {}, passwords = []):
    """ Add/update info for 'device'.  
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @param device: The hostname of the device to add/update 
    @type device: string/hostname
    @param info: A dict of properities to save with the entry. 
    @type info: dict 
    @param logins: A dict of username:password login entries. 
    @type logins: dict   
    @param psafeLoc: Full path to the psafe file to edit.   
    @type psafeLoc: string/filepath 
    @return: None 
    
    """
    safe = None
    for passwd in passwords:
        try:
            safe = PWSafe3(filename = psafeLoc, mode = 'RW', password = passwd)
            log.debug("%r worked for %r" % (passwd, psafeLoc))
            break
        except:
            log.debug("%r failed for %r" % (passwd, psafeLoc))
    if not safe:
        log.debug("Unable to open the safe %r" % psafeLoc)
    safe.lock()
    try:
        log.debug("Locked safe %r" % psafeLoc)
        # Existing entries
        eeLogins = {}
        eeInfo = {}
        
        # Determine the group name
        s = device.split('/')
        deviceFull = s[-1].split('.')
        deviceHost = deviceFull[0]     
        groupList = s[:-1]+[deviceHost,]       
        groupMatch = '.'.join(groupList)
        
        for record in safe.getEntries():
            if '.'.join(record.getGroup()) == groupMatch:
                log.debug("Found a record that is in the device's group: %r" % record)
                if record.getTitle() == 'Logins':
                    log.debug("Found login %r" % record.getUsername())
                    eeLogins[record.getUsername()] = record
                elif record.getTitle() == 'Info':
                    log.debug("Found info %r" % record.getUsername())
                    eeInfo[record.getUsername()] = record                    
                else:
                    log.debug("Related but unknown: %r" % record.getTitle())
            else:
                log.debug("Ignoring %r" % record)
        for username, password in logins.items():
            if eeLogins.has_key(username):                
                eeLogins[username].setPassword(password)
                log.debug("Set %r to %r" % (eeLogins[username], password))
            else:
                r = Record()
                r.setGroup(groupList)
                r.setTitle('Logins')
                r.setUsername(username)
                r.setPassword(password)
                r.setUUID(uuid4())                
                safe.records.append(r)
                log.debug("Added record %r" % r)
        for key_, val in info.items():
            if eeInfo.has_key(key_):                
                eeInfo[key_].setPassword(val)
                log.debug("Set %r to %r" % (eeInfo[key_], val))
            else:
                r = Record()
                r.setGroup(groupList)
                r.setTitle('Info')
                r.setUsername(key_)
                if '\n' in val:
                    r.setPassword("See Note")
                    r.setNote(val)
                else:
                    r.setPassword(val)
                r.setUUID(uuid4())                
                safe.records.append(r)
                log.debug("Added record %r" % r)
        
        log.debug("Saving safe")
        safe.save()
        log.debug("Saved safe")
    finally:
        log.debug("Unlocking safe %r" % psafeLoc)
        safe.unlock()
        log.debug("Unlocked %r" % psafeLoc)

@task(ignore_result = False, expires = 24 * 60 * 60)
def addUpdateByUUID(loc, uuid, psafeLoc, passwords = [], info = {}):
    """ Add/update info for 'device'.  
    @param loc: The filesystem path to the psafe repo. 
    @type loc: string/file path
    @param passwords: A list of zero or more passwords to use when decrypting safes. 
    @type passwords: List of strings
    @param uuid: UUID of the entry. Will be created if it doesn't already exist. If there are multiple matches then only one will be updated. 
    @type uuid: string/uuid 
    @param info: A dict of properties to save. Must match Record object props.  
    @type info: dict  
    @return: None 
    """
    safe = None
    for passwd in passwords:
        try:
            safe = PWSafe3(filename = psafeLoc, mode = 'RW', password = passwd)
            log.debug("%r worked for %r" % (passwd, psafeLoc))
            break
        except:
            log.debug("%r failed for %r" % (passwd, psafeLoc))
    if not safe:
        log.debug("Unable to open the safe %r" % psafeLoc)
    safe.lock()
    try:
        log.debug("Locked safe %r" % psafeLoc)
        r = None
        for record in safe.records:
            if record.getUUID() == uuid:
                log.debug("Found a match: %r" % record)
                r = record
        if not r:
            r = Record()
            safe.records.append(r) 
        log.debug("Record to add/update: %r" % r)
        
        for name, val in info.items():
            r[name] = val
        
        log.debug("Saving safe")
        safe.save()
        log.debug("Saved safe")
    finally:
        log.debug("Unlocking safe %r" % psafeLoc)
        safe.unlock()
        log.debug("Unlocked %r" % psafeLoc)



