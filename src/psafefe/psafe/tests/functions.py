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
from psafefe.psafe.tests.tasks import LivePsafeTestCase 

class FunctionsPsafeTests(LivePsafeTestCase):
    """ Commonly used functions tests """
    
    def _setUp(self):
        from django.conf import settings
        from django.contrib.auth.models import User, Group
        from psafefe.psafe.models import *
        # Double check nothing is left over
        assert MemPasswordEntryHistory.objects.all().count() == 0
        assert MemPsafeEntry.objects.all().count() == 0
        assert MemPSafe.objects.all().count() == 0
        assert PasswordSafe.objects.all().count() == 0
        assert PasswordSafeRepo.objects.all().count() <= 1
        
        # Most of these tests will need users
        newUsers = self.createUsers(userCount = 3, adminCount = 1, userStartAt = 0, adminStartAt = 0)
        # Setup groups
        self.groupsByRepo = {}
        
        # TODO: Move all of this to fixtures
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
        
        # Make sure all known safes are pre-loaded - Needs to run 
        # after the repos are defined so it knows what folders to
        # look in. 
        from psafefe.psafe.tasks import refreshSafesFull
        r = refreshSafesFull.delay(maxRefresh = None)  # @UndefinedVariable 
        r.wait()
        
    def _tearDown(self):
        from django.conf import settings
        from django.contrib.auth.models import User, Group
        from psafefe.psafe.models import *
                                        
    def test_getPersonalPsafeRepo_simple(self):
        from django.conf import settings
        from psafefe.psafe.functions import getPersonalPsafeRepo 
        pRepo = getPersonalPsafeRepo()
        
        # Tests
        self.assertEqual(pRepo.path, settings.PSAFE_PERSONAL_PATH, "Didn't set the personal psafe path correctly")
        self.assertEqual(pRepo.pk, settings.PSAFE_PERSONAL_PK, "Didn't set the personal psafe PK right")
        
        # Not really important
        self.assertEqual(pRepo.name, "Personal Password Safes", "Didn't set the personal psafe name right")
        
        # Dir tests
        self.assertTrue(os.access(pRepo.path, os.R_OK | os.W_OK))
        
        
    def test_getUsersPersonalSafe_simple(self):
        from django.conf import settings
        from psafefe.psafe.functions import getUsersPersonalSafe
        # Create a user with read/write access to the test safe repo
        username, user = self.getUser(
                                      userClass = 'user',
                                      groups = [
                                                self.groupsByRepo['testsafes']['writes'],
                                                self.groupsByRepo['testsafes']['reads'],
                                                ],
                                      )
        userpass = self.getUserPass(user = user)
        
        mySafe = getUsersPersonalSafe(
                                      user = user,
                                      userPassword = userpass,
                                      wait = True,
                                      )
        self.assertTrue(mySafe)
        
        myMemSafe = mySafe.getCached(canLoad = False)
        self.assertTrue(myMemSafe, "Failed to automatically create and load a new safe and it's cached entry")
        
    def test_get_and_set_DatabasePasswordByUser_simple(self):
        from django.conf import settings
        from psafefe.psafe.models import *
        from psafefe.psafe.functions import getUsersPersonalSafe, getDatabasePasswordByUser, setDatabasePasswordByUser
        # Create a user with read/write access to the test safe repo
        username, user = self.getUser(
                                      userClass = 'user',
                                      groups = [
                                                self.groupsByRepo['testsafes']['writes'],
                                                self.groupsByRepo['testsafes']['reads'],
                                                ],
                                      )
        userpass = self.getUserPass(user = user)
        
        mySafe = getUsersPersonalSafe(
                                      user = user,
                                      userPassword = userpass,
                                      wait = True,
                                      )
        self.assertTrue(mySafe)
        
        # Get the DB we're working with
        db = PasswordSafe.objects.get(
                                      repo = self.groupsByRepo['testsafes']['repo'],
                                      filename__endswith = "simple.psafe3",
                                      )
        
        # Save the DB password
        setDatabasePasswordByUser(
                                  user = user,
                                  userPassword = userpass,
                                  psafe = db,
                                  psafePassword = 'bogus12345',
                                  wait = True,
                                  )
        
        # Try with ppsafe set 
        dbPassword = getDatabasePasswordByUser(
                                               user = user,
                                               userPassword = userpass,
                                               psafe = db,
                                               ppsafe = mySafe,
                                               wait = True,
                                               )  
        self.assertEqual(dbPassword, 'bogus12345', "Password for simple.psafe3 is wrong or has changed. Was trying without passing in a personal psafe to getDatabasePasswordByUser")      
        # try without ppsafe set
        dbPassword = getDatabasePasswordByUser(
                                               user = user,
                                               userPassword = userpass,
                                               psafe = db,
                                               ppsafe = None,
                                               wait = True,
                                               )
        self.assertEqual(dbPassword, 'bogus12345', "Password for simple.psafe3 is wrong or has changed. Was trying with passing in a personal psafe to getDatabasePasswordByUser")
        
        # TODO: Add in checks for user/userPassword/psafe/ppsafe not matching
        # TODO: Add in checks for user not having perms to the repo that ppsafe is in
        
        
    
    
