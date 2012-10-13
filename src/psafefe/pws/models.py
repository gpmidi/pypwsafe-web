from django.db import models
from psafefe.pws.validators import *
from django.contrib.auth.models import User, Group
from uuid import uuid4
import os, os.path, sys

# Create your models here.
class PasswordSafeRepo(models.Model):
    """ A place where psafes can be stored """
    class Meta:
        ordering = [
                    'name',
                    ]
        verbose_name = "Password Safe Repo"
        verbose_name_plural = "Password Safe Repos"
        permissions = (
                       # ('can_read', 'Can sync all safes in this repo'),
                       )
                
    name = models.CharField(
                            null = False,
                            blank = False,
                            max_length = 255,
                            verbose_name = "Name",
                            help_text = "A human readable name for the password safe repository",
                            )
    path = models.CharField(
                            null = False,
                            blank = False,
                            max_length = 1024 * 1024,
                            verbose_name = "Server Location",
                            help_text = "The location on the server of the password safes",
                            validators = [
                                        validate_r_ok,
                                        ],
                            )
    adminGroups = models.ManyToManyField(
                                           Group,
                                           verbose_name = "Admin Groups",
                                           help_text = "Groups that have administrative access to this repo",
                                           related_name = "admin_groups_rlt",
                                           )
    readAllowGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Read-Allow Groups",
                                               help_text = "Groups that have read access to this repo",
                                               related_name = "read_allow_groups_rlt",
                                               )
    writeAllowGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Write-Allow Groups",
                                               help_text = "Groups that have write access to this repo",
                                               related_name = "write_allow_groups_rlt",
                                               )
    # These are applied before the allows
    readDenyGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Read-Deny Groups",
                                               help_text = "Groups that do not have read access to this repo. This overrides the read-allow groups list. ",
                                               related_name = "read_deny_groups_rlt",
                                               )
    writeDenyGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Write-Deny Groups",
                                               help_text = "Groups that do not have write access to this repo. This overrides the write-allow groups list. ",
                                               related_name = "write_deny_groups_rlt",
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
        
    def user_can_access(self, user, mode = "R"):
        """ Returns true if the user has access to this repo. Mode should
        be "R" for read only, "RW" for read/write, or "A" for admin. """
        if mode == "R":
            return (self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups)) or self._in_group(user, self.adminGroups)
        elif mode == "A":
            return self._in_group(user, self.adminGroups)
        elif mode == "RW":
            return (self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups) and self._in_group(user, self.writeAllowGroups) and not self._in_group(user, self.writeDenyGroups)) or self._in_group(user, self.adminGroups)
        else:
            raise ValueError, "Mode %r is not a valid mode" % mode
    
class PasswordSafe(models.Model):
    """ Keep a record of all psafes that we should track
    Do NOT store any confidential info from the safe. 
    """
    class Meta:
        ordering = [
                    'repo',
                    'filename',
                    ]
        verbose_name = "Password Safe"
        verbose_name_plural = "Password Safes"
        unique_together = (
                           # Can't do this because filename is too long
                           # TODO: Add a filename_md5 or something 
                           # ('filename','repo'),
                           )
        permissions = (
                       # ('can_sync', 'Can sync individual safes'),
                       )
    
    filename = models.FilePathField(
                                # The system should note this safe as "missing" if it can't be found atm. 
                                null = False,
                                max_length = 1024 * 1024,
                                verbose_name = "Password Safe Path",
                                help_text = "The full path to the password safe from the worker's perspective",
                                # FIXME: Change this to a configurable setting
                                path = '/var/lib/safes/',
                                recursive = True,
                                )
    repo = models.ForeignKey(
                             PasswordSafeRepo,
                             verbose_name = "Repository",
                             help_text = "The password safe repository that this safe resides in",
                             )
    
    owner = models.ForeignKey(
                              User,
                              # If null it's a normal psafe, if set, it's a personal psafe
                              null = True,
                              verbose_name = "Owner",
                              help_text = "The owning user of the password safe",
                              related_name = 'owner_rlt',
                              ) 
    
    def psafePath(self):
        """ Returns the full path on the server to the psafe file """
        return os.path.join(self.repo.path, self.filename)
    
