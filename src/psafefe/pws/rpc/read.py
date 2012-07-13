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
''' Psafe read related functions. 

@author: Paulson McIntyre <paul@gpmidi.net>
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from uuid import UUID

# Entry methods
@rpcmethod(name = 'psafe.read.getEntryByPK', signature = ['struct', 'string', 'string', 'int'])
@auth
def get(username, password, entPK, **kw):
    """ Return a struct representing the requested entry 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The database id of the entry to return. 
    @type entPK: int
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    """
    try:
        ent = MemPsafeEntry.objects.get(pk = entPK)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError
