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
''' Tasks to update/delete/create password entries and password safes
All write activity is done synchronisly to reduce the possibility of
data loss and conflicts. 
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
# from celery.task import task #@UnresolvedImport
from celery.decorators import task  # @UnresolvedImport
from psafefe.psafe.models import *  # @UnusedWildImport
from psafefe.psafe.errors import *  # @UnusedWildImport
from pypwsafe import PWSafe3, Record
from psafefe.psafe.tasks.load import loadSafe
import datetime
from socket import getfqdn
import re 

import logging
log = logging.getLogger("psafefe.psafe.tasks.write")
log.debug('initing')

@task()
def newSafe(psafePK, psafePassword, userPK = None, dbName = None, dbDesc = None):
    """ Create a new, empty psafe (on disk) and then
    load it into the cache. Will not error or overwrite
    duplicate safes. """
    if userPK:
        user = User.objects.get(pk = userPK)
    else:
        user = None
    psafe = PasswordSafe.objects.get(pk = psafePK)
    
    pypwsafe = PWSafe3(
                     filename = psafe.psafePath(),
                     password = psafePassword,
                     mode = "RW",
                     )
    # Set details
    pypwsafe.setVersion()
    pypwsafe.setTimeStampOfLastSave(datetime.datetime.now())
    pypwsafe.setUUID()
    pypwsafe.setLastSaveApp('PyPWSafe')
    if user:
        pypwsafe.setLastSaveUser(user.username)
    try:
        pypwsafe.setLastSaveHost(getfqdn())
    except:
        log.debug("Failed to set/save hostname in new psafe")
    if dbName:
        pypwsafe.setDbName(dbName)
    if dbDesc:
        pypwsafe.setDbDesc(dbDesc)
    pypwsafe.save()
    assert loadSafe(psafe_pk = psafePK, password = psafePassword, force = True)


def _matchVale(record, fieldName, fieldValue):
    try:
        actualValue = record[fieldName]
    except KeyError, e:
        log.debug("Field %r from %r doesn't exist. No match. ", fieldName, record, fieldValue)
        return False
    if fieldValue == fieldName:
        log.debug("Field %r from %r is %r. Matched exact value. ", fieldName, record, fieldValue)
        return True
    log.debug("Field %r from %r is %r, not %r", fieldName, record, actualValue, fieldValue)
    return False

def _matchRE(record, fieldName, cmpRegex):
    try:
        actualValue = record[fieldName]
    except KeyError, e:
        log.debug("Field %r from %r doesn't exist. No match. ", fieldName, record)
        return False
    if cmpRegex.match(actualValue):
        log.debug("Field %r from %r is %r. Matched regex. ", fieldName, record, actualValue)
        return True
    log.debug("Field %r from %r is %r. No match. ", fieldName, record, actualValue)
    return False
 
def _findRecords(psafe, pypwsafe, refilters, vfilters, maxMatches = None):
    """ Yields all records matching the given query. """
    # Compile the regexs
    refiltersCmp = {}
    for name, raw in refilters.items():
        log.debug("Compiling %r for %r", raw, name)
        refiltersCmp[name] = re.compile(refilters)
    
    matchCount = 0
    for record in pypwsafe.getEntries():
        log.log(5, "Checking %r", record)
        matched = True
        for field, mvalue in vfilters.items():
            if not _matchVale(record = record, fieldName = field, fieldValue = mvalue):
                log.log(5, "Value match for %r failed", field)
                matched = False
                break
        # Skip slow stuff, if possible
        if not matched:
            continue
        for field, cmpRegex in refiltersCmp.items():
            if not _matchRE(record = record, fieldName = field, cmpRegex = cmpRegex):
                matched = False
                break
        # Found one
        if matched:
            matchCount += 1
            if maxMatches is None or matchCount < maxMatches:
                log.debug("Match %r: %r", matchCount, record)
                yield record
            else:
                log.debug("%r matched but over maxMatches", record)
                break
    log.debug("Done finding records. Found %r", matchCount)

def _update(psafe, pypwsafe, action, refilters, vfilters, changes, maxMatches = None):
    """ Update the matching records 
    @return: The number of records that were updated. 
    """
    assert action == "update"
    toUpdate = _findRecords(psafe = psafe, pypwsafe = pypwsafe, refilters = refilters, vfilters = vfilters, maxMatches = None)
    for record in toUpdate:
        for fieldName, newValue in changes.items():
            try:
                record[fieldName] = newValue
            except KeyError, e:
                log.info("Couldn't set field %r on %r to %r", fieldName, record, newValue)
    return len(toUpdate)

def _delete(psafe, pypwsafe, action, refilters, vfilters, maxMatches = None):
    """ Delete the matching records 
    @return: The number of records that were deleted. 
    """
    assert action == "delete"
    toUpdate = _findRecords(psafe = psafe, pypwsafe = pypwsafe, refilters = refilters, vfilters = vfilters, maxMatches = None)
    deleteCount = 0
    for record in toUpdate:
        try:
            pypwsafe.records.remove(record)
            deleteCount += 1
        except ValueError, e:
            log.warn("Failed to find and delete record %r in %r", record, pypwsafe)
    return deleteCount

def _add(psafe, pypwsafe, action, changes):
    """ Add the given record
    @return: The newly created Record 
    """
    assert action == "add"
    record = Record()
    for fieldName, fieldValue in changes.items():
        try:
            record[fieldName] = fieldValue
        except KeyError, e:
            log.warn("Failed to update %r with %r=%r", record, fieldName, fieldValue)
    pypwsafe.records.insert(0, record)
    return record

def _addUpdate(psafe, pypwsafe, action, refilters, vfilters, changes, maxMatches = None):
    """ Update the matching records 
    @return: dict(
            updated = The number of records updated. Includes the one added if no updates are made. 
            newRecord = None or the newly created record object. 
            )
    """
    assert action == "add-update"
    log.debug("Going to add-update %r", pypwsafe)
    updatedCount = _update(psafe = psafe, pypwsafe = pypwsafe, action = action, refilters = refilters, vfilters = vfilters, changes = changes, maxMatches = maxMatches)
    if updatedCount == 0:
        log.debug("Didn't update any records. Creating a new one")
        record = _add(psafe = psafe, pypwsafe = pypwsafe, action = action, changes = changes)
        return dict(updated = 1, newRecord = record)
    return dict(updated = updatedCount, newRecord = None)

def _action(psafe, pypwsafe, **kw):
    """ Run the requested action. Returns the number of changes made. """
    if not 'action' in kw:
        raise KeyError, "The 'action' isn't specified"
    if kw['action'] == 'add':
        r = _add(psafe = psafe, pypwsafe = pypwsafe, **kw)
        return 1
    if kw['action'] == 'add-update':
        r = _addUpdate(psafe = psafe, pypwsafe = pypwsafe, **kw)
        return r['updated']
    if kw['action'] == 'delete':
        return _delete(psafe = psafe, pypwsafe = pypwsafe, **kw)
    if kw['action'] == 'update':
        return _update(psafe = psafe, pypwsafe = pypwsafe, **kw)
    raise ValueError, "%r isn't a valid action" % kw['action']

# TODO: Add support for values based on regexs
# TODO: Add support for using Django templates and maybe value substitution from other fields in value setting
@task()
def modifyEntries(
                  psafePK,
                  psafePassword,
                  # Changes to make
                  actions = [],
                  # What to do if an error occurs
                  # fail: If an error occurs, stop immediately. No changes should be made to the psafe. 
                  # skip: Skip over the action that failed and complete the other actions. 
                  onError = 'fail',
                  # If True, update the memory-db cache after the update is done
                  updateCache = True,
                  ):
    """ Add/update/delete/etc multiple password safe entries.
    @note: If no actions are given, then the safe will be opened and then saved. Post-save may be slightly different than pre-save in such cases, if the pypwsafe api "corrects" anything or does anything differently. 
    
    Valid actions: 
        * update
        * delete
        * add
        * add-update
        
    The <Options> are <field name>:<new field value> pairs as used in MemPsafeEntry's todict method. 
    The <Regex Filters> are <Field Name>:<Uncompiled Regex> pairs. 
    The <Value Filters> are <Field Name>:<Field Value> pairs. The field value must be EXACTLY the same. 
    All regex and value filters must match for the entry to be updated. 
    The 'maxMatches' field indicates the maximum number of entries to change/delete/etc. Defaults to None, 
        which means no limit.
     
    Example actions: 
    actions=[
                # Add an entry.
                {
                'action':'add',
                'changes':{ <Options> },
                },
                
                # Delete all matching entries. 
                {
                'action':'delete',
                'refilters':{ <Regex Filters>, },
                'vfilters':{ <Value Filters>, },
                'maxMatches': 5, 
                },
                
                # Update matching entries.
                { 
                'action:'update',
                'refilters':{ <Regex Filters>, },
                'vfilters':{ <Value Filters>, },
                'changes':{ <Options> },
                'maxMatches': 5, 
                },
                
                # Update one or more existing entries. If no matching entries are found, then create a new one.
                { 
                'action':'add-update':,
                'refilters':{ <Regex Filters>, },
                'vfilters':{ <Value Filters>, },
                'changes':{ <options> },
                'maxMatches': 5,
                },
            ]
    """
    psafe = PasswordSafe.objects.get(pk = psafePK)
    log.debug("Going to change entries from %r", psafe)
    pypwsafe = PWSafe3(
                     filename = psafe.psafePath(),
                     password = psafePassword,
                     mode = "RW",
                     )
    ret = dict(errors = [], changes = 0)
    log.debug("Going to lock safe")
    pypwsafe.lock()    
    try:
        log.debug("Lock acquired")
        for action in actions:
            log.debug("Going to %r", action['action'])
            if onError == "fail":
                ret['changes'] += _action(psafe = psafe, pypwsafe = pypwsafe, **action)
            elif onError == "skip":
                try:
                    ret['changes'] += _action(psafe = psafe, pypwsafe = pypwsafe, **action)
                except Exception, e:
                    log.warn("There was an error while updating %r per %r", pypwsafe, action)
                    ret['errors'].append(
                                         dict(
                                              action = action,
                                              error = repr(e),
                                              traceback = None,  # TODO: Add traceback
                                              )
                                         )
        pypwsafe.save()
    finally:
        log.debug("Going to unlock safe")
        pypwsafe.unlock()
    
    if updateCache:
        log.debug("Going to update the ram cache for %r", pypwsafe)
        assert loadSafe(psafe_pk = psafePK, password = psafePassword, force = True)
        
    return ret
    
   
