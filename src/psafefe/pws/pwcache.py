'''
Created on Jul 13, 2012

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
'''
from pypwsafe import PWSafe3, ispsafe3
import os

import logging
log = logging.getLogger(__name__)

class CachedPWS(PWSafe3):
    """ A cache-enabled psafe object """
    # Safe's last-modified timestamp
    psafeLastModified = None
    # The psafe file's size
    psafeSize = None
        
    def __init__(self, filename, password):
        log.debug("Caching safe %r" % filename)
        PWSafe3.__init__(self, filename = filename, password = password, mode = "RO")
        log.debug("Safe loading completed for %r" % self)
    
    def _setSafeInfo(self):
        """ Update the psafe file info used to check for changes """
        log.debug("Updating safe file stats for %r" % self)
        assert os.access(self.filename, os.R_OK)
        info = os.stat(self.filename)
        self.psafeLastModified = info.st_mtime
        self.psafeSize = info.st_size        
    
    def _changed(self):
        """ Return true if there have been any changes per quick checks """
        assert os.access(self.filename, os.R_OK)
        info = os.stat(self.filename)
        if self.psafeLastModified != info.st_mtime:
            log.debug("Quick info changed st_mtime: %r vs %r" % (self.psafeLastModified, info.st_mtime))
            return True
        if self.psafeSize != info.st_size:
            log.debug("Quick info changed st_size: %r vs %r" % (self.psafeSize, info.st_size))
            return True
        log.debug("%r hasn't changed" % self)
        return False        
        
    def checkUpdate(self):
        """ Check common, quick info to make sure the safe doesn't need to be updated """
        if self._changed():
            log.debug("Loading existing safe from %r" % self.filename)
            self.fl = open(self.filename, 'rb')
            try:
                self.flfull = self.fl.read()
                log.debug("Full data len: %d" % len(self.flfull))                
                # Read in file
                self.load()
            finally:
                self.fl.close()
            # Update file stats
            self._setSafeInfo()
        else:
            log.debug("%r hasn't changed" % self)

class PWSLocCache(object):
    """ Holds one or more cached psafe objects (read-only)
    
    """
    # Path to safes
    loc = None
    
    # Known safe passwords
    safePasswords = []
    
    # Psafe password lookup function
    passwordLookup = None
    
    # Cached safe objects
    # Full filename path is the key
    safes = {}
    
    def __init__(self, loc, safePasswords = [], passwordLookup = None):        
        self.loc = loc
        self.safePasswords = safePasswords
        self.passwordLookup = passwordLookup
        # Check for safes to cache!
        self.checkLoc()
    
    def addSafePassword(self, passwd, update = False):
        """ Add a safe decryption password to known list. If update
        is true, the check for safes that can be decrypted with the
        new password """
        if not passwd in self.safePasswords:
            self.safePasswords.append(passwd)
            log.debug("Added %r to safe decryption list" % passwd)
        else:
            log.debug("Already have %r in the list" % passwd)
        
        if update:
            self.checkLoc()
        else:
            log.debug("Not going to check for new safes")
        
    
    def checkLoc(self):
        """ Check for new, uncached safes in the loc """
        log.debug("Going to check for new safes to cache in %r" % self.loc)
        assert os.access(self.loc, os.R_OK)
        
        for (dirpath, dirnames, filenames) in os.walk(self.loc):
            log.debug("Checking %r" % dirpath)
            for filename in filenames:
                fil = os.path.join(self.loc, dirpath, filename)
                log.debug("Check file %r" % fil)
                if self.safes.has_key(fil):
                    log.debug("Safe exists. Updating")
                    self.safes[fil].checkUpdate()
                else:
                    log.debug("Don't have in cache...adding")
                    if ispsafe3(fil):
                        if self.passwordLookup:
                            try:
                                pw = self.passwordLookup(fil)
                                if not pw in self.safePasswords:
                                    self.safePasswords.append(pw)
                                    log.debug("Added %r to safe pw list" % (pw))
                            except Exception, e:
                                log.warn("Tried doing a pw lookup for %r. Error: %r" % (fil, e))
                        for passwd in self.safePasswords:
                            log.debug("Trying to open safe %r with %r" % (fil, passwd))
                            try:
                                self.safes[fil] = CachedPWS(fil, passwd)
                                log.debug("Cached %r" % self.safes[fil])
                            except:
                                log.debug("Failed to open safe %r with %r" % (fil, passwd))
                    else:
                        log.debug("Not a psafe v3")
        log.debug("Done walking safe loc")
        
    def checkUpdateAll(self):
        """ Check and, if required, update all safes """
        log.debug("Going to check/update all for %r" % self.loc)
        for fil, safe in self.safes.items():
            log.debug("Going to check/update %r" % fil)
            safe.checkUpdate()
        log.debug("Done updating all for %r" % self.loc)
        
    def getSafe(self, psafeLoc, passwords = []):
        """ Fetch a psafe object. Safe password MUST be one of the passwords passed in. """
        log.debug("Asked to fetch psafe %r using %r" % (psafeLoc, passwords))
        if self.safes.has_key(psafeLoc):
            self.safes[psafeLoc].checkUpdate()
            for pw in passwords:
                if self.safes[psafeLoc].password == pw:
                    log.debug("Returning safe %r" % self.safes[psafeLoc])
                    return self.safes[psafeLoc]
            log.debug("No passwords matched")
            return None
        else:
            log.debug("Not cached")
            update = False
            for pw in passwords:
                if not pw in self.safePasswords:
                    log.debug("%r isn't already listed" % pw)
                    update = True
                    self.safePasswords.append(pw)
                else:
                    log.debug("%r is already in our list. Ignoring. " % pw)
            if update:
                self.checkLoc()
                log.debug("Updated cached safes")
            # Check again for cached safe
            if self.safes.has_key(psafeLoc):
                self.safes[psafeLoc].checkUpdate()
                for pw in passwords:
                    if self.safes[psafeLoc].password == pw:
                        log.debug("Returning safe %r" % self.safes[psafeLoc])
                        return self.safes[psafeLoc]
                log.debug("No passwords matched")
                return None
            log.debug("Couldn't load %r using %r" % (psafeLoc, passwords))
            return None
                
# Primary psafe cache object storage
cache = {}

def addLoc(loc, passwords = [], passwordLookup = None):
    """ Add psafe loading/cache for the given loc """
    global cache
    if cache.has_key(loc):
        log.debug("Already have %r" % loc)
        for passwd in passwords:
            cache[loc].addSafePassword(passwd, update = True)
    else:
        log.debug("Don't have %r. Adding with %r & %r" % (loc, passwords, passwordLookup))
        cache[loc] = PWSLocCache(loc, safePasswords = passwords, passwordLookup = passwordLookup)
    log.debug("Done adding %r" % loc)

def getSafe(loc, psafeLoc, passwords = []):
    """ Return the cached (or freshly loaded) psafe from psafeLoc using 
    the given passwords. Returns None if no safe exists or no passwords
    match. 
    """
    global cache
    assert cache.has_key(loc)
    log.debug("%r: Getting safe from %r using %r" % (loc, psafeLoc, passwords))
    
    return cache[loc].getSafe(psafeLoc, passwords)



