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
''' Semi-static pages
Created on Feb 3, 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
'''
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render_to_response
from django.db.models import Q
from django.template import RequestContext
from django.views.decorators.cache import cache_page

def rootIndex(req):
    return render_to_response(
                              'index.html',
                              dict(
                                    ),
                              context_instance = RequestContext(req),
                              )

def index(req):
    return render_to_response(
                              'psafe/static/index.html',
                              dict(
                                    ),
                              context_instance = RequestContext(req),
                              )

def robots(req):
    return render_to_response(
                              'psafe/static/robots.txt',
                             dict(
                                    ),
                              context_instance = RequestContext(req),
                              )

def crossdomain(req):
    return render_to_response(
                              'psafe/static/crossdomain.xml',
                              dict(
                                    ),
                              context_instance = RequestContext(req),
                              )




