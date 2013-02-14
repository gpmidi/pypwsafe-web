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
''' Tasks to load/reload password safes into the cache. 
All read-only activity is done async. All write activity
is done sync to reduce the possibility of data loss or 
conflicts. 

Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import os, os.path
# from celery.task import task #@UnresolvedImport
from celery.decorators import task, periodic_task  # @UnresolvedImport
from psafefe.psafe.models import *
from psafefe.psafe.errors import *
from pypwsafe import PWSafe3, ispsafe3
import stat
from datetime import timedelta

import logging
log = logging.getLogger("psafefe.psafe.tasks.load")
log.debug('initing')


@periodic_task(run_every=timedelta(minutes=5), ignore_result=False, expires=5 * 60)
def refreshSafesByTimestamp(psafePKs=None):
    """ Refresh any safes that have a different timestamp and/or different size. Not 100%
    accurate, but it'll catch most cases. 
    @return: int, the number of safes refreshed
    @param psafePKs: A list of PasswordSafe PKs that should be refreshed. Check all if None. 
    @type psafePKs: None or a list of ints
    @note: Not 100% accurate.    
    """
    refreshed = 0
    if psafePKs is None:
        safes = PasswordSafe.objects.all().select_related()
    else:
        safes = PasswordSafe.objects.filter(pk__in=psafePKs).select_related()

    for safe in safes:
        try:
            log.debug("Going to see if %r needs to be updated", safe)
            memsafe = safe.mempsafe
            memsafe.onUse()
            if loadSafe(psafe_pk=safe.pk, password=memsafe.dbPassword, force=False):
                refreshed += 1
            else:
                log.debug("No need to refresh %r", safe)
        except MemPSafe.DoesNotExist, e:
            log.debug("Failed to find mempsafe for %r" % safe)

    log.debug("Updated %r safes", refreshed)
    return refreshed


@periodic_task(run_every=timedelta(minutes=60), ignore_result=False, expires=30 * 60)
def refreshSafesQuick(maxRefresh=5):
    """ Perform a full refresh of the most frequently used safes
    @return: int, the number of safes refreshed
    @param maxRefresh: The max number of safes to refresh
    @type maxRefresh: Int  
    @note: Only the top few safes 
    """
    memSafes = MemPSafe.objects.all().order_by('-entryLastRefreshed').select_related()[:maxRefresh]
    safes = map(lambda s: s.safe.pk, memSafes)

    return refreshListedSafes(psafePKs=safes)


@periodic_task(run_every=timedelta(hours=24), ignore_result=False, expires=24 * 60 * 60)
def refreshSafesFull(maxRefresh=None):
    """ Perform a full refresh of all
    @return: int, the number of safes refreshed
    @param maxRefresh: The max number of safes to refresh
    @type maxRefresh: Int  
    @note: Only the top few safes 
    """
    safes = []

    if maxRefresh is None:
        psafes = PasswordSafe.objects.all()
    else:
        psafes = PasswordSafe.objects.all()[:maxRefresh]
    for psafe in psafes:
        safes.append(psafe.pk)

    return refreshListedSafes(psafePKs=safes)


@task(expires=60 * 60 * 24)
def refreshListedSafes(psafePKs=[]):
    """ Refresh the cache for all list safes 
    @return: int, number of safes refreshed
    """
    refreshed = 0
    for psafePK in psafePKs:
        try:
            psafe = PasswordSafe.objects.get(pk=psafePK)
            mempsafe = psafe.mempsafe
            #mempsafe.onUpdate()
            log.debug("Going to update cache for %r", psafe)

            assert loadSafe(psafe_pk=psafePK, password=mempsafe.dbPassword, force=True)

            mempsafe.onRefresh()
            refreshed += 1
            log.debug("Done updaing cache for %r", psafe)
        except Exception, e:
            log.exception("Failed to update the cache for PSafe ID %r" % psafePK)

    log.debug("Done refreshing cache for %r safes", refreshed)
    return refreshed


@periodic_task(run_every=timedelta(minutes=30), ignore_result=False, expires=60 * 30)
def findSafes(repoByName=None, repoByPK=None):
    """ Walk the given repos (or all if repos=None) and find any new psafe files. 
    @return: int, the number of new safes located
    @param repoByName: A list of repos names to update. Use None to update all.  
    @type repoByName: list of strings
    @param repoByPK: A list of repos PKs to update. Use None to update all.  
    @type repoByPK: list of ints
    @note: Both repoByName and repoByPK must be None to update all. Otherwise the union of the two will be used. 
    @note: Set to ignore result by default. Make sure to override this if you want a value.   
    """
    cnt = 0
    repos = []
    if repoByName:
        repos += [PasswordSafeRepo.objects.get(name=repo) for repo in repoByName]
    if repoByPK:
        repos += [PasswordSafeRepo.objects.get(pk=repo) for repo in repoByPK]
    if len(repos) == 0 and repoByName is None and repoByPK is None:
        repos = PasswordSafeRepo.objects.all()
    for repo in repos:
        cnt += findSafesInRepo(repo.pk)
    return cnt


@task(ignore_result=False, expires=60 * 60)
def findSafesInRepo(repoPK):
    """ Find all safes in the given repo and make sure there is a PasswordSafe object for it
    @param repoPK: The PK of the repo to check
    @type repoPK: int  
    @return: int, the number of safes located
    @note: Set to ignore result by default. Make sure to override this if you want a value or plan to .wait().
    """
    repo = PasswordSafeRepo.objects.get(pk=repoPK)
    cnt = 0
    for (dirpath, dirnames, filenames) in os.walk(repo.path):
        for filename in filenames:
            ext = filename.split('.')[-1].lower()
            if ext == "psafe3":
                # Dont' just assume - validate!
                if ispsafe3(os.path.join(repo.path, dirpath, filename)):
                    fullFilePath = os.path.join(dirpath, filename)
                    filePath = fullFilePath.lstrip(repo.path)
                    # Make sure it doesn't already exists in the DB
                    if PasswordSafe.objects.filter(
                                                   filename=filePath,
                                                   repo=repo,
                                                   ).count() == 0:
                        try:
                            pws = PasswordSafe(
                                             filename=filePath,
                                             repo=repo,
                                             )
                            pws.save()
                            cnt += 1
                        except:
                            pass

    return cnt


@task()
def loadSafe(psafe_pk, password, force=False):
    """ Cache  password safe. Returns True if the cache was updated. False otherwise. 
    Try not to change any PKs if it's not required. 
    """
    try:
        psafe = PasswordSafe.objects.get(pk=psafe_pk)
    except PasswordSafe.DoesNotExist:
        raise PasswordSafeDoesntExist, "Password safe object %r doesn't exist" % psafe_pk
    if not os.access(psafe.psafePath(), os.R_OK):
        raise NoAccessToPasswordSafe, "Can't read psafe file %r" % psafe.psafePath()
    try:
        memPSafe = MemPSafe.objects.get(safe=psafe)
    except MemPSafe.DoesNotExist:
        memPSafe = MemPSafe(
                            safe=psafe,
                            )

    # Check if we need to
    if not force and os.stat(psafe.psafePath())[stat.ST_MTIME] == memPSafe.fileLastModified and memPSafe.fileLastSize == os.stat(psafe.psafePath())[stat.ST_SIZE]:
        return False

    # Save first, just in case it changes while we are reading already read data
    import datetime
    memPSafe.fileLastModified = datetime.datetime.fromtimestamp(os.stat(psafe.psafePath())[stat.ST_MTIME])
    memPSafe.fileLastSize = os.stat(psafe.psafePath())[stat.ST_SIZE]

    # Let standard psafe errors travel on up
    pypwsafe = PWSafe3(
                     filename=psafe.psafePath(),
                     password=password,
                     mode="R",
                     )
    # Make sure the main pws object's uuid is right
    if pypwsafe.getUUID() != psafe.uuid:
        psafe.uuid = pypwsafe.getUUID()
        psafe.save()
    # Update/set attributes
    memPSafe.uuid = pypwsafe.getUUID()
    memPSafe.dbName = pypwsafe.getDbName()
    memPSafe.dbDescription = pypwsafe.getDbDesc()
    memPSafe.dbPassword = password
    memPSafe.dbTimeStampOfLastSafe = pypwsafe.getTimeStampOfLastSave()
    memPSafe.dbLastSaveApp = pypwsafe.getLastSaveApp()
    memPSafe.dbLastSaveHost = pypwsafe.getLastSaveHost()
    memPSafe.dbLastSaveUser = pypwsafe.getLastSaveUser()

    memPSafe.save()

    # All entries in db. Remove from list after updating.
    remaining = {}
    safeEntries = MemPsafeEntry.objects.filter(safe=memPSafe)
    for i in safeEntries:
        if i.uuid in remaining:
            raise DuplicateUUIDError("Entry %r has the same UUID as %r" % (i, remaining[i.uuid]))
        else:
            remaining[unicode(i.uuid)] = i

    updated = {}

    for entry in pypwsafe.getEntries():
        # Find the entry to create it (by uuid)
        uuid = unicode(entry.getUUID())
        log.debug("Looking for entry UUID of %r in a list of %d entries", uuid,memPSafe.mempsafeentry_set.all().count())
        try:
            memEntry = memPSafe.mempsafeentry_set.get(uuid=uuid)
            log.debug("Found entry %r for %r",memEntry,uuid)
            updated[memEntry.uuid] = remaining.pop(memEntry.uuid)
            log.debug("Removed from remaining dict")
        except MemPsafeEntry.DoesNotExist, e:
            log.exception("Failed to find entry for %r. Creating new entry. ",uuid)
            memEntry = MemPsafeEntry(
                                   safe=memPSafe,
                                   uuid=uuid,
                                   )
        # FIXME: Add in a catch for multiple entries found with the same UUID for the same safe
        # Update the entry
        memEntry.group = '.'.join(entry.getGroup())
        memEntry.title = entry.getTitle()
        memEntry.username = entry.getUsername()
        memEntry.notes = entry.getNote()
        memEntry.password = entry.getPassword()
        memEntry.creationTime = entry.getCreated()
        memEntry.passwordModTime = entry.getPasswordModified()
        memEntry.accessTime = entry.getLastAccess()
        memEntry.passwordExpiryTime = entry.getExpires()
        memEntry.modTime = entry.getEntryModified()
        memEntry.url = entry.getURL()
        memEntry.autotype = entry.getAutoType()
        memEntry.runCommand = entry.getRunCommand()
        memEntry.email = entry.getEmail()

        memEntry.save()

        org = {}
        for i in MemPasswordEntryHistory.objects.filter(entry=memEntry):
            org[repr(i.creationTime) + i.password] = i
        found = []
        for old in memEntry.getHistory():
            t = repr(repr(old['saved']) + old['password'])
            if t in org:
                memOld = org[t]
                del org[t]
                found.append(memOld)
            else:
                memOld = MemPasswordEntryHistory(entry=memEntry, password=old['password'], creationTime=old['saved'])
                memOld.save()
        # Remove all other old password entries
        for removedEntry in org.values():
            removedEntry.delete()
    # Remove all other entries
    for removedEntry in remaining.values():
        removedEntry.delete()

    memPSafe.onRefresh()

    return True

