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
""" RPC methods to create/update/delete whole password safes. 
Created on Aug 21, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
"""
import logging
log = logging.getLogger('psafefe.psafe.rpc.write.safe')

import os.path
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from uuid import UUID


@rpcmethod(
           name='psafe.write.safe.createSafe',
           signature=[
                      # Return value
                      'struct',
                      # Args
                      'string', 'string', 'int', 'string',
                      'string', 'string', 'string'
                      ],
           )
@auth
def createSafe(
               username, password, repoID, safePassword,
               safeFileName, safeName, safeDesc='', **kw
               ):
    safeFileName = os.path.basename(safeFileName)

    nsafe = PasswordSafe(
                           filename=safeFileName,
                           repo=PasswordSafeRepo.objects.get(pk=repoID),
                           owner=kw['user'],
                           )
    nsafe.save()
    from psafefe.psafe.tasks import *
    newSafe.delay(# @UndefinedVariable
                  psafePK=nsafe.pk,
                  psafePassword=safePassword,
                  userPK=kw['user'].pk,
                  dbName=safeName,
                  dbDesc=safeDesc,
                  ).wait()
    # Try to refresh so we get the right info
    nsafe = PasswordSafe.objects.get(pk=nsafe.pk)
    ret = {
           'uuid':nsafe.uuid,
           'pk':nsafe.pk,
           }
    return ret
