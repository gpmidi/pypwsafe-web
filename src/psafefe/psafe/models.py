# !/usr/bin/env python
# ===============================================================================
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
# ===============================================================================
from django.db import models
from uuid import uuid4
from django.contrib.auth.models import User, Group
from psafefe.psafe.validators import *
from os.path import join
from django.contrib import admin

import logging
log = logging.getLogger("psafefe.psafe.models")
log.debug('initing')


class PasswordSafeRepo(models.Model):
    """ A place where psafes can be stored """
    class Meta:
        ordering = [
                    'name',
                    ]
        verbose_name = "Password Safe Repo"
        verbose_name_plural = "Password Safe Repos"
        permissions = (
                       ('can_sync', 'Can sync all safes in this repo'),
                       )

    name = models.CharField(
                            null=False,
                            blank=False,
                            unique=True,
                            max_length=255,
                            verbose_name="Name",
                            help_text="A human readable name for the password safe repository",
                            )
    path = models.TextField(
                            null=False,
                            blank=False,
                            max_length=1024 * 1024,
                            verbose_name="Server Location",
                            help_text="The location on the server of the password safes",
                            validators=[
                                        validate_r_ok,
                                        ],
                            )
    adminGroups = models.ManyToManyField(
                                           Group,
                                           blank=True,
                                           verbose_name="Admin Groups",
                                           help_text="Groups that have administrative access to this repo",
                                           related_name="admin_groups_set",
                                           )
    readAllowGroups = models.ManyToManyField(
                                               Group,
                                               blank=True,
                                               verbose_name="Read-Allow Groups",
                                               help_text="Groups that have read access to this repo",
                                               related_name="read_allow_groups_set",
                                               )
    writeAllowGroups = models.ManyToManyField(
                                               Group,
                                               blank=True,
                                               verbose_name="Write-Allow Groups",
                                               help_text="Groups that have write access to this repo",
                                               related_name="write_allow_groups_set",
                                               )
    # These are applied before the allows
    readDenyGroups = models.ManyToManyField(
                                               Group,
                                               blank=True,
                                               verbose_name="Read-Deny Groups",
                                               help_text="Groups that do not have read access to this repo. This overrides the read-allow groups list. ",
                                               related_name="read_deny_groups_set",
                                               )
    writeDenyGroups = models.ManyToManyField(
                                               Group,
                                               blank=True,
                                               verbose_name="Write-Deny Groups",
                                               help_text="Groups that do not have write access to this repo. This overrides the write-allow groups list. ",
                                               related_name="write_deny_groups_set",
                                               )

    # Helpers
    def _in_group(self, user, group_relate):
        """ Returns true if the user is in a group that is part of the many-to-many
        related group listed above """
        groups = user.groups.all()
        for group in groups:
            if group in group_relate.all():
                return True
        return False

    def user_can_access(self, user, mode="R"):
        """ Returns true if the user has access to this repo. Mode should
        be "R" for read only, "RW" for read/write, or "A" for admin. """
        from django.conf import settings
        # Supers can do anything
        if user.is_superuser:
            return True
        # Don't allow any traditional access to the personal psafes
        if self.pk == settings.PSAFE_PERSONAL_PK:
            return False
        # Normal perms
        if mode.upper() == "R":
            return (self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups)) or self._in_group(user, self.adminGroups)
        elif mode.upper() == "A":
            return self._in_group(user, self.adminGroups)
        elif mode.upper() == "RW":
            return (self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups) and self._in_group(user, self.writeAllowGroups) and not self._in_group(user, self.writeDenyGroups)) or self._in_group(user, self.adminGroups)
        else:
            raise ValueError, "Mode %r is not a valid mode" % mode

    # Random ideas:
    # Include options for storing all safes in a GIT repo
    # Add per-user permissions too
    # Add user-created groups or something to that effect
admin.site.register(PasswordSafeRepo)


class PasswordSafe(models.Model):
    """ Keep a record of all psafes that we should track
    Do NOT store any confidential info from the safe. 
    """
    class Meta:
        ordering = [
                    'repo',
                    'filename',
                    'uuid',
                    ]
        verbose_name = "Password Safe"
        verbose_name_plural = "Password Safes"
        unique_together = (
                           # Can't do this because filename is too long
                           # TODO: Add a filename_md5 or something
                           # ('filename','repo'),
                           )
        permissions = (
                       ('can_sync', 'Can sync individual safes'),
                       )
    """ 
    @ivar uuid: The password safe GUID as a UUID
    @type uuid: A UUID as a string
    @warning: This field WILL be incorrect if the safe has never been decrypted.    
    """
    uuid = models.CharField(# FIXME: Should this be null=true for when the safe hasn't been decrypted?
                            # can't use as PK as two psafes may have the same uuid (yes, this *shouldn't* happen, but people use copy/paste to copy safes sometimes. )
                            # primary_key = True,
                            null=False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default=lambda: str(uuid4()),
                            max_length=36,
                            verbose_name="UUID",
                            help_text="Password Safe GUID",
                            editable=False,
                            )
    # FIXME: Change this to a filepath field - Watch out for max_length restrictions
    filename = models.TextField(
                                # The system should note this safe as "missing" if
                                # the safe file can't be found atm. This is done by
                                # setting filename to null.
                                # The root of this entry is relative to the repo's path
                                null=True,
                                max_length=1024 * 1024,
                                verbose_name="Password Safe Path",
                                help_text="The full path to the password safe from the worker's perspective",
                                )
    repo = models.ForeignKey(
                             PasswordSafeRepo,
                             verbose_name="Repository",
                             help_text="The password safe repository that this safe resides in",
                             )

    owner = models.ForeignKey(
                              User,
                              # If null it's a normal psafe, if set, it's a personal psafe
                              null=True,
                              editable=False,
                              verbose_name="Owner",
                              help_text="The owning user of the password safe",
                              )

    def __init__(self, *args, **kw):
        models.Model.__init__(self, *args, **kw)
        self.log = logging.getLogger("psafefe.psafe.tasks.load.PasswordSafe.%r" % self)
        self.log.debug('initing')

    def psafePath(self):
        """ Returns the full path on the server to the psafe file """
        return join(self.repo.path, self.filename)

    def getCached(self, canLoad=False, user=None, userPassword=None):
        """ Return the RAM only cached data for this safe. 
        @param canLoad: Indicates what to do if the entry doesn't exist. False: Error out. True: Load the safe then return the obj.  
        """
        self.log.debug("Getting cached copy")
        from psafefe.psafe.errors import EntryNotCached
        # Can't load without the password
        from django.contrib.auth.models import User
        if not isinstance(user, User):
            canLoad = False
            self.log.debug("Can't load due to lack of valid user (%r)" % user)
        if not userPassword:
            canLoad = False
            self.log.debug("Can't load due to lack of valid password for user (%r)" % userPassword)
        try:
            return self.mempsafe
        except MemPSafe.DoesNotExist, e:
            if canLoad:
                self.log.debug("Going to try loading")
                try:
                    from psafefe.psafe.tasks.load import  loadSafe
                    from psafefe.psafe.functions import getDatabasePasswordByUser
                    dbPassword = getDatabasePasswordByUser(
                                              user=user,
                                              userPassword=userPassword,
                                              psafe=self,
                                              wait=True,
                                              )
                    ls = loadSafe.delay(psafe_pk=self.pk, password=dbPassword, force=False)  # @UndefinedVariable
                    ls.wait()
                    # Make sure to prevent inf. recursion if the load fails
                    return self.getCached(canLoad=False)
                except Exception, e:
                    raise EntryNotCached, "%r doesn't have a cached entry and loading failed with %r" % (self, e)
            else:
                raise EntryNotCached, "%r doesn't have a cached entry and loading is disabled. " % self

    def onUse(self):
        """ Record psafe access """
admin.site.register(PasswordSafe)


# Memory resident tables
class MemPSafe(models.Model):
    """ Represent a cache'd psafe """
    safe = models.OneToOneField(
                             PasswordSafe,
                             null=False,
                             verbose_name="Password Safe File",
                             help_text="Reference to the psafe file",
                             editable=False,
                             )
    uuid = models.CharField(
                            # can't use as PK as two psafes may have the same uuid
                            # primary_key = True,
                            null=False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default=lambda: str(uuid4()),
                            max_length=36,
                            verbose_name="UUID",
                            help_text="Password Safe GUID",
                            editable=False,
                            )
    dbName = models.TextField(
                              null=True,
                              default=None,
                              blank=True,
                              max_length=1024 * 1024,
                              verbose_name="Database Name",
                              )
    dbDescription = models.TextField(
                                     null=True,
                                     blank=True,
                                     default=None,
                                     max_length=1024 * 1024 * 1024,
                                     verbose_name="Database Description",
                                     )
    dbPassword = models.TextField(
                                  null=False,
                                  blank=True,
                                  default="bogus12345",
                                  max_length=1024 * 1024,
                                  verbose_name="Database Password",
                                  )
    dbTimeStampOfLastSave = models.DateTimeField(
                                                 null=True,
                                                 verbose_name="Last Save",
                                                 help_text="Date/Time of last Password Safe save",
                                                 )
    dbLastSaveApp = models.CharField(
                                     null=True,
                                     verbose_name="Last Save App",
                                     max_length=4096,
                                     )
    dbLastSaveHost = models.CharField(
                                     null=True,
                                     verbose_name="Last Save Host",
                                     max_length=4096,
                                     )
    dbLastSaveUser = models.CharField(
                                     null=True,
                                     verbose_name="Last Save User",
                                     max_length=4096,
                                     )
    # Cache params
    fileLastModified = models.DateTimeField(
                                            null=False,
                                            verbose_name="File Last Modified",
                                            editable=False,
                                            )
    fileLastSize = models.IntegerField(
                                      null=False,
                                      verbose_name="File Last Size",
                                      editable=False,
                                      )
    entryUseCount = models.IntegerField(
                                      null=False,
                                      verbose_name="Use Count",
                                      help_text="The number of times that this entry has been used. ",
                                      default=0,
                                      editable=False,
                                      )
    entryLastRefreshed = models.DateTimeField(
                                            null=False,
                                            verbose_name="Cache Entry Last Refreshed",
                                            help_text="The last time the cached entry was updated from the on-disk safe",
                                            editable=False,
                                            auto_now_add=True,
                                            )

    def onRefresh(self, save=True):
        """ This cache entry has been refreshed """
        import datetime
        self.entryUseCount = 0
        self.entryLastRefreshed = datetime.datetime.now()
        if save:
            self.save()

    def onUse(self, save=True):
        """ The safe has been used """
        self.entryUseCount += 1
        if save:
            self.save()

    # TODO: Add in safe HMAC validation checks too

    def todict(self, getEntries=True, getEntryHistory=True):
        """ Return an XML-RPC safe dictionary of the data. Null 
        fields are deleted! """
        ret = {
             'PK':self.safe.pk,
             'UUID':self.uuid,
             'Name':self.dbName,
             'Description':self.dbDescription,
             'Password':self.dbPassword,
             'Last Save Time':self.dbTimeStampOfLastSave,
             'Last Save App':self.dbLastSaveApp,
             'Last Save Host':self.dbLastSaveHost,
             'Last Save User':self.dbLastSaveUser,
             }
        if getEntries:
            ret['Entries'] = [i.todict(history=getEntryHistory) for i in self.mempsafeentry_set.all()]
        for k, v in ret.items():
            if v is None:
                del ret[k]
        return ret
admin.site.register(MemPSafe)


class MemPsafeEntry(models.Model):
    """ Represent a cached password safe entry """
    class Meta:
        unique_together = (
                           # TODO: Is this really a safe assumption?
                           ('safe', 'uuid'),
                           )
    safe = models.ForeignKey(
                             MemPSafe,
                             null=False,
                             verbose_name="Password Safe",
                             )
    # FIXME: UUID field?
    uuid = models.CharField(
                            # can't use as PK as two psafes may have the same uuid
                            # primary_key = True,
                            null=False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default=lambda: str(uuid4()),
                            max_length=36,
                            verbose_name="UUID",
                            help_text="Entry GUID",
                            editable=False,
                            )
    group = models.CharField(
                             null=True,
                             default=None,
                             max_length=4096,
                             verbose_name="Group",
                             help_text="Dot separated group listing for the entry",
                             )
    title = models.CharField(
                             null=True,
                             default=None,
                             max_length=4096,
                             verbose_name="Title",
                             )
    username = models.CharField(
                             null=True,
                             default=None,
                             max_length=4096,
                             verbose_name="Username",
                             )
    notes = models.TextField(
                             null=True,
                             default=None,
                             max_length=1024 * 1024,
                             verbose_name="Notes",
                             )
    password = models.CharField(
                             null=True,
                             default=None,
                             max_length=4096,
                             verbose_name="Password",
                             )
    creationTime = models.DateTimeField(
                                        null=True,
                                        default=None,
                                        verbose_name="Creation Time",
                                        )
    passwordModTime = models.DateTimeField(
                                           null=True,
                                           default=None,
                                           verbose_name="Password Last Modification Time",
                                           )
    accessTime = models.DateTimeField(
                                      null=True,
                                      default=None,
                                      verbose_name="Last Access Time",
                                      )
    passwordExpiryTime = models.DateTimeField(
                                              null=True,
                                              verbose_name="Password Expiry Time",
                                              )
    modTime = models.DateTimeField(
                                   null=True,
                                   verbose_name="Last Modification Time",
                                   )
    # Don't use a URL field - We don't want to risk any validation
    # Plus psafe doesn't guarantee it's a URL
    url = models.CharField(
                           null=True,
                           default=None,
                           max_length=4096,
                           verbose_name="URL",
                           )
    autotype = models.CharField(
                           null=True,
                           default=None,
                           max_length=4096,
                           verbose_name="Autotype String",
                           )
    runCommand = models.CharField(
                           null=True,
                           default=None,
                           max_length=4096,
                           verbose_name="Run Command",
                           )
    # Don't use an email field as psafe doesn't make any guarantees about the value
    email = models.CharField(
                           null=True,
                           default=None,
                           max_length=4096,
                           verbose_name="Email",
                           )

    def todict(self, history=True):
        """ Return an XML-RPC safe dictionary of the data. Null 
        fields are deleted! Field names (keys) should be identical
        to those in pypwsafe's records. """
        ret = {
             'PK':self.pk,
             'UUID':self.uuid,
             'Group':self.group,
             'Title':self.title,
             'Username':self.username,
             'Notes':self.notes,
             'Password':self.password,
             'Creation Time':self.creationTime,
             'Password Last Modification Time':self.passwordModTime,
             'Last Access Time':self.accessTime,
             'Password Expiry':self.passwordExpiryTime,
             'Entry Last Modification Time':self.modTime,
             'URL':self.url,
             'AutoType':self.autotype,
             'Run Command':self.runCommand,
             'Email':self.email,
             }
        if history:
            ret['History'] = [dict(Password=i.password, CreationTime=i.creationTime) for i in self.mempasswordentryhistory_set.all()]
        for k, v in ret.items():
            if v is None:
                del ret[k]
        return ret

    def onUse(self):
        """ The entry was used. Update the counters on our parent mempsafe """
        self.safe.onUse()

    def getHistory(self):
        """ Return all old passwords, in order """
        return self.mempasswordentryhistory_set.all().order_by('creationTime')
admin.site.register(MemPsafeEntry)


class MemPasswordEntryHistory(models.Model):
    """ Old passwords for the given entry """
    entry = models.ForeignKey(
                              MemPsafeEntry,
                              null=False,
                              verbose_name="Entry",
                              )
    password = models.CharField(
                             null=True,
                             default=None,
                             max_length=4096,
                             verbose_name="Old Password",
                             )
    creationTime = models.DateTimeField(
                                        null=True,
                                        default=None,
                                        verbose_name="Creation Time",
                                        )
admin.site.register(MemPasswordEntryHistory)

