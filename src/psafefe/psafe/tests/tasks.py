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
''' Tests related to async tasks via celeryd
Created on Oct 14, 2012

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
'''
from django.test import TestCase
from django.test.utils import override_settings
import datetime
import time, os, os.path, sys, stat

class LivePsafeTestCase(TestCase):
    """ Test cases that will prep for action against psafe files 
    @note: Sub classes can define _setUp and _tearDown functions if they need setup/teardown. 
    @warning: Any subclasses that override setUp/tearDown/etc methods should call the same on their superclass
    @ivar users: A dict of all users that were created for tests. dict(username=user object)
    @ivar availAdmins: A dict of all unused admin users. dict(username=user object)
    @ivar availUsers: A dict of all unused users. dict(username=user object)
    """
    
    def setUp(self):
        """ Create psafe test dir and copy sample psafe files to it. """
        from django.conf import settings
        from shutil import copytree
        
        assert os.access(settings.TEST_BASE, os.R_OK | os.W_OK)
        
        # Copy all needed dirs to the temp loc
        for udir in settings.TEST_REQUIRED_DIRS:
            tpath = os.path.join(settings.TEST_BASE, udir)
            spath = os.path.join(settings.TEST_SOURCE_BASE, udir)
            copytree(spath, tpath)
        # Make a place for the personal safes
        os.makedirs(settings.PSAFE_PERSONAL_PATH, 0755)
        
        # Create users - Disabled as many tests probably won't need users
        # newUsers = self.createUsers(userCount = 10, adminCount = 5, userStartAt = 0, adminStartAt = 0)
                
        # Call equivalent in sub-classes
        if hasattr(self, '_setUp'):
            return self._setUp()
        
    def tearDown(self):
        """ Cleanup """
        from django.conf import settings
        assert settings.TEST_BASE
        from shutil import rmtree
        for udir in settings.TEST_REQUIRED_DIRS:
            tpath = os.path.join(settings.TEST_BASE, udir)
            # TODO: Consider adding an onerror and/or ignore_errors to the rmtree calls
            rmtree(tpath)
        rmtree(settings.PSAFE_PERSONAL_PATH)
        
        # Get rid of the test users
        for username, user in self.users.items():
            user.delete()
            del self.users[username]
        
        # Call equivalent in sub-classes
        if hasattr(self, '_tearDown'):
            return self._tearDown()
        
    
    @classmethod
    def setUpClass(cls):
        # Find where the helper test files are located
        required_dirs = [
                         'userfiles',
                         'test_safes',
                         'templates',
                         'static',
                         'media',
                         'src',
                         ]

        base = None
        possibles = sys.path
        possibles.append(os.getcwd())
        for i in sys.path:
            possibles.append("%s/../" % i)
        # Test most likely places first
        possibles.reverse()
        # Test each loc to see if the needed folders are in it 
        for testLoc in possibles:
            for testDir in required_dirs:
                loc = os.path.join(testLoc, testDir)
                if os.access(loc, os.R_OK):
                    base = loc
                    break
            if base:
                break
        
        # Didn't find any dir with the folders we need
        if not base:            
            from psafefe.psafe.errors import CantLocateHelperFiles
            raise CantLocateHelperFiles, "Can't locate the dir with needed test files. Required: %r " % required_dirs
        
        # Make a location to store mutable test files
        from tempfile import mkdtemp
        tbase = mkdtemp(prefix = "psafefe-")
        
        # Make sure the required psafe repos are around
        from psafefe.psafe.models import *
        try:
            ps = PasswordSafeRepo.objects.get(pk = 1)
            ps.path = os.path.join(tbase, 'personal_psafes')
            ps.save()
        except PasswordSafeRepo.DoesNotExist:
            from django.conf import settings
            ps = PasswordSafeRepo(
                                  pk = settings.PSAFE_PERSONAL_PK,
                                  name = "Personal Password Safes",
                                  path = os.path.join(tbase, 'personal_psafes'),
                                  )
            ps.save()
        
        # Override settings
        newSettings = dict(
                         PSAFE_PERSONAL_PATH = os.path.join(tbase, 'personal_psafes'),
                         TEST_REQUIRED_DIRS = required_dirs,
                         TEST_BASE = tbase,
                         TEST_SOURCE_BASE = base,
                         MEDIA_ROOT = os.path.join(tbase, 'media'),
                         STATIC_ROOT = os.path.join(tbase, 'static'),
                         TEMPLATE_DIRS = os.path.join(tbase, 'templates'),
                         DEFAULT_FILE_STORAGE = os.path.join(tbase, 'userfiles'),
                         )
        # Add TEST_DIR_XXX settings
        for d in required_dirs:
            newSettings["TEST_DIR_%s" % (d.upper())] = os.path.join(tbase, d)
        
        # Set settings
        cls.override_settings(
                              **newSettings
                              )(cls)
        
    @classmethod
    def tearDownClass(cls):
        """ Cleanup any leftover files """
        from django.conf import settings
        assert settings.TEST_BASE
        from shutil import rmtree
        rmtree(settings.TEST_BASE)
        
    def createUsers(self, userCount = 10, adminCount = 10, userStartAt = 0, adminStartAt = 0):
        """ Create more test users and/or admins. Stores user objects in self.users
        by username. If *StartAt is None, then start at a random value. 
        @return: A dict containing a list of newly created users. e.g. dict(admins=dict(adminName=adminObj),users={}) 
        """
        from django.contrib.auth.models import User, Group
        self._initUserVars()
            
        from random import randint
        if userStartAt is None:
            userStartAt = randint(1024, 65535)
        
        if adminStartAt is None:
            adminStartAt = randint(1024, 65535)
        
        added = dict(admins = [], users = [])
        for i in xrange(adminStartAt, adminCount + adminStartAt):
            name = 'admin%d' % i
            assert not name in self.users
            # Create and save as one
            self.users[name] = User.objects.create_superuser(name, 'admin%d@localhost' % i, 'bogus12345')
            # Change the pw to something easier to use
            self.users[name].set_password(self.getUserPass(self, user = self.users[name]))
            self.users[name].save()
            added['admin'][name] = self.users[name]
            self.availAdmins[name] = self.users[name]
        
        for i in xrange(userStartAt, userCount + userStartAt):
            name = 'user%d' % i
            assert not name in self.users
            # Create and save as one
            self.users[name] = User.objects.create(name, 'user1@localhost' % i, 'abc123')
            # Change the pw to something easier to use
            self.users[name].set_password(self.getUserPass(self, user = self.users[name]))
            self.users[name].save()
            added['user'][name] = self.users[name]
            self.availUsers[name] = self.users[name]
            
        return added
    
    def _initUserVars(self):
        """ Make sure the user tracking vars are around and correct """
        if not hasattr(self, 'users'):
            self.users = {}
        if not hasattr(self, 'availUsers'):
            self.availUsers = {}
        if not hasattr(self, 'availAdmins'):
            self.availAdmins = {}
    
    def getUserPass(self, userName = None, user = None):
        """ Returns the password for the given user. """
        from django.contrib.auth.models import User, Group
        assert userName or user
        if user and userName:
            assert user.username == userName
        
        if not userName:
            userName = user.username
        
        if not user:
            user = User.objects.get(username = userName)
        
        if user.is_superuser:
            return "bogus12345-%d" % user.pk
        return "abc123-%d" % user.pk
                
    def getUser(self, userClass = 'user', groups = []):
        """ Returns a new user of the requested type 
        @param userClass: The type of user to create. user or admin
        @param groups: The groups the user should be added to. Should be a Group object or the PK of a group object. 
        @return: tuple(username,user object)
        """
        from django.contrib.auth.models import User, Group
        self._initUserVars()
        
        if userClass == 'user':
            if len(self.availUsers) == 0:
                self.createUsers(userCount = 10, adminCount = 0, userStartAt = None, adminStartAt = None)
            user = self.availUsers.popitem()
        elif userClass == 'admin':
            if len(self.availAdmins) == 0:
                self.createUsers(userCount = 0, adminCount = 10, userStartAt = None, adminStartAt = None)
            user = self.availAdmins.popitem()
        else:
            raise ValueError, "%r isn't a valid userClass. Expected 'user' or 'admin'. " % userClass
        
        # Put in groups
        for group in groups:
            if not isinstance(group, Group):
                group = Group.objects.get(pk = group)
            user.groups.add(group)
        if len(groups) > 0:
            user.save()
        
# class PersonalPsafeTests(LivePsafeTestCase):
#    def _setUp(self):
#        """ Prep for test """
#    
#    def test_something(self):
#        pass
    
class LoadPsafeTests(LivePsafeTestCase):
    """ Password safe loading related tests """
    
    def _setUp(self):
        from django.conf import settings
        from django.contrib.auth.models import User, Group
        from psafefe.psafe.models import *
        # Most of these tests will need users
        newUsers = self.createUsers(userCount = 3, adminCount = 1, userStartAt = 0, adminStartAt = 0)
        # Setup groups
        self.groupsByRepo = {}
        
        # Repo = Test Safes
        self.groupsByRepo['testsafes'] = {}
        self.groupsByRepo['testsafes']['repo'] = PasswordSafeRepo(
                                                              name = 'Test Safes',
                                                              path = settings.TEST_DIR_TEST_SAFES,
                                                              )
        # Admin users
        self.groupsByRepo['testsafes']['admins'] = Group.objects.create(name = "Repo One Admins")
        self.groupsByRepo['testsafes']['repo'].adminGroups.add(self.groupsByRepo['testsafes']['admins'])
        # Read access
        self.groupsByRepo['testsafes']['reads'] = Group.objects.create(name = "Repo One Read Users")
        self.groupsByRepo['testsafes']['repo'].readAllowGroups.add(self.groupsByRepo['testsafes']['reads'])
        # Write Access
        self.groupsByRepo['testsafes']['writes'] = Group.objects.create(name = "Repo One Write Users")
        self.groupsByRepo['testsafes']['repo'].writeAllowGroups.add(self.groupsByRepo['testsafes']['writes'])
        # Save group changes
        self.groupsByRepo['testsafes']['repo'].save()
        
    def _tearDown(self):
        self.groupsByRepo = {}
        
    def test_loadSafe_simple(self):
        import os, sys, os.path
        from django.conf import settings
        from psafefe.psafe.models import *
        testSafeRepo = self.groupsByRepo['testsafes']['repo']
        testSafes = os.listdir(testSafeRepo.path)
        # Ignore non-psafe3 files
        testSafes = filter(lambda fil: fil.endswith('.psafe3'), testSafes)
        
        # Load all safes in the test_safes dir/repo
        from psafefe.psafe.tasks.load import loadSafe
        for safe in testSafes:
            filePath = os.path.join(testSafeRepo.path, safe)
            try:
                psafeObj = PasswordSafe.objects.get(
                                                    filename = filePath,
                                                    repo = testSafeRepo,
                                                    )
            except PasswordSafe.DoesNotExist: 
                psafeObj = PasswordSafe(
                                        filename = filePath,
                                        repo = testSafeRepo,
                                        )
                psafeObj.save()
                
            res = loadSafe.delay(# @UndefinedVariable
                           psafe_pk = psafeObj.pk,
                           password = 'bogus12345',
                           force = False,
                           )
            self.assertTrue(res, "Failed to load safe %r" % safe)
            
            res = loadSafe.delay(# @UndefinedVariable
                           psafe_pk = psafeObj.pk,
                           password = 'bogus12345',
                           force = False,
                           )
            self.assertFalse(res, "Loaded safe %r when we shouldn't have" % safe)
            
            res = loadSafe.delay(# @UndefinedVariable
                           psafe_pk = psafeObj.pk,
                           password = 'bogus12345',
                           force = True,
                           )
            self.assertTrue(res, "Failed forcibly reload safe %r" % safe)
            
            
    
