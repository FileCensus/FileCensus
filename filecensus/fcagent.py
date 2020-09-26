"""

FileCensus Scanning Agent for UNIX ( Python Edition ) v1.0.3

Copyright (C) 2002 Intermine Pty. Ltd.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

--------------------------------------------------------------------------

This script is designed to collect file system information from UNIX
based systems for analysis by Intermines FileCensus product. Visit
http://www.intermine.com for details about FileCensus.

The file format is based on Python data structures with the option of
adding inline block compression at a later point.  This is main reason
for not selecting an XML based data format. The order that this script
iterates through the file system is very important and changing it will
break compatibility with the FileCensus Server.

We have tested this script on a range of platforms including Linux ( on
Intel, IBM zSeries and Itanium processors ), BSD, Solaris and Tru64 on
Alpha.

Some sites have been interested to use the SSH Secure Copy software to
move the images from remote servers to the FileCensus server.  If you
make changes that you would like us to consider supporting please email
them to support@intermine.com.  Also if you imbed this script into your
NAS device or operating system please let us know! We are interested to
support the use of FileCensus on a range of storage devices.

"""

# Paths listed here will not be scanned for information.
#
excluded_paths = [ '/dev/', '/mnt/', '/proc/' ]

# You can set the server in this script or supply it on the command line.
#
server_address = ''

from sys import argv, exit
if server_address == '':
  if len( argv) == 1:
    print 'You need to supply the address of the FileCensus Server on the command line'
    print 'Use the format:'
    print '  python fcagent.py servername.or.ipaddress:port'
    exit( 1)
  else:
    server_address = argv[ 1]

import httplib
import time
import os
from stat import *
from statvfs import *
from os.path import isdir, islink, ismount
from grp import getgrgid
from pwd import getpwuid, getpwnam
from struct import pack
from string import upper, split
from zlib import compress

has_statvfs = 0
if 'statvfs' in dir( os):
  has_statvfs = 1

class imxp_encoder:

  def __init__( self, filename):
    self.output = open( filename, 'wb')
    self.output.write( 'IMXP')
    self.output.write( pack( '<I', 0))

    flags = 2

    self.output.write( pack( '<I', flags))
    self.queue = []
    self.codes = {}
    self.count = {}

    self.uids = {}
    self.gids = {}
    self.names = {}

  def append( self, name, record):
    self.count[ name] = self.count[ name] + 1
    self.queue.append( ( self.codes[ name], record ) )
    if len( self.queue) == 256:
      self.flush()

  def define( self, name, about):
    self.codes[ name] = len( self.codes) + 1
    self.count[ name] = 0
    self.queue.append( ( 0, name, about ) )
    if len( self.queue) == 256:
      self.flush()

  def flush( self):
    block_txt = repr( self.queue)
    block_zlib = compress( block_txt)
    self.output.write( pack( '<I', len( block_zlib)))
    self.output.write( block_zlib)
    self.output.write( pack( '<I', len( block_txt)))
    self.queue = []

  def close( self):
    if len( self.queue):
      self.flush()
    self.output.write( pack( '<I', 0))
    self.output.close()

def upload( filename, destination):

  id = 0

  while 1:

    http = httplib.HTTP( destination)
    http.putrequest( 'PUT', '/transfer_xpi/accept?version=1&id=%s' % id)
    http.endheaders()

    errcode, errmsg, headers = http.getreply()

    if not errcode == 200:
      sleep( 5 * 60)
      continue

    body = http.getfile()
    reply = eval( body.readline(), {}, {} )
    body.close()

    id = reply[ 0]

    if   reply[ 1] == 'pause':  time.sleep( reply[ 2] )

    elif reply[ 1] == 'begin':

      file = open( filename, 'rb')

      file.seek( 0, 2)
      bytes = file.tell()
      file.seek( 0, 0)

      http = httplib.HTTP( destination)
      http.putrequest( 'PUT', '/transfer_xpi/upload?version=1&id=%s' % id)
      http.putheader( 'Content-Length', str( bytes))
      http.endheaders()

      data = file.read( 8096)
      while data:
        http.send( data )
        data = file.read( 8096)

      errcode, errmsg, headers = http.getreply()

      if not errcode == 200:
        raise TransferError, 'Error code ' + header[ 1] + ' returned from server'

      return

def lookup_uid( db, uid):
  if db.uids.has_key( uid): return
  db.uids[ uid] = 1

  try:
    pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell = getpwuid( uid)
    db.append( 'uid', ( pw_name, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) )
    db.names[ pw_name] = 1
  except:
    pass

def lookup_name( db, name):
  if db.names.has_key( name): return
  db.names[ name] = 1

  try:
    pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell = getpwnam( name)
    db.append( 'uid', ( pw_name, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) )
    db.uids[ pw_uid] = 1
  except:
    pass

def lookup_gid( db, gid):

  if db.gids.has_key( gid): return
  db.gids[ gid] = 1

  try:
    gr_name, gr_passwd, gr_gid, gr_mem = getgrgid( gid)
    for name in gr_mem:
      if db.names.has_key( name): continue
      lookup_name( db, name)

    db.append( 'gid', ( gr_name, gr_gid, gr_mem ))
  except:
    pass

def scan( db, pathname):

  if pathname in excluded_paths:
    return

  path_islink = 0
  if islink( pathname[:-1]):
    db.append( 'link', ( os.readlink( pathname[:-1] ) ) )
    path_islink = 1

  sentry = os.stat( pathname)
  lookup_uid( db, sentry[ ST_UID ] )
  lookup_gid( db, sentry[ ST_GID ] )
  db.append( 'path', ( pathname, sentry ) )

  if path_islink:
    return

  if ismount( pathname):
    if has_statvfs:
      filesystem = os.statvfs( pathname)
      if filesystem[ F_BLOCKS] > 0:
        db.append( 'mount', ( pathname, filesystem ) )

  subdirs = []
  for name in os.listdir( pathname):

    fullname = pathname + name

    try:
      sentry = os.stat( fullname)
      smode = sentry[ ST_MODE]

      if S_ISDIR( smode):

        subdirs.append( fullname)

      elif S_ISREG( smode):

        if islink( fullname):
          db.append( 'link', ( os.readlink( fullname) ) )

        lookup_uid( db, sentry[ ST_UID ] )
        lookup_gid( db, sentry[ ST_GID ] )
        db.append( 'file', ( name, sentry ) )

    except:
      pass

  for subdir in subdirs:
    scan( db, subdir + '/')

def setup( db):

  about = {}

  about[ 'hostname'] = httplib.socket.gethostname()
  about[ 'osname'] = os.name
  about[ 'oschar'] = ( os.curdir, os.pardir, os.pathsep, os.sep )
  about[ 'localtime'] = time.localtime(time.time())
  about[ 'timezone'] = time.timezone
  about[ 'tzname'] = time.tzname

  db.define( 'system', about )

  about = {}
  indexes = {}
  for name in [ 'mode', 'ino', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']:
    exec 'indexes[ name] = ST_' + upper( name)
  about[ 'indexes'] = indexes
  db.define( 'path', about)

  about = {}
  indexes = {}
  for name in [ 'bsize', 'frsize', 'blocks', 'bfree', 'bavail', 'files', 'ffree', 'favail', 'flag', 'namemax']:
    exec 'indexes[ name] = F_' + upper( name)
  about[ 'indexes'] = indexes
  db.define( 'mount', about)

  about = {}
  indexes = {}
  for name in [ 'mode', 'ino', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']:
    exec 'indexes[ name] = ST_' + upper( name)
  about[ 'indexes'] = indexes
  db.define( 'file', about)

  db.define( 'uid', {} )
  db.define( 'gid', {} )
  db.define( 'link', {} )

if __name__ == '__main__':

  db = imxp_encoder( 'image.xpi')
  setup( db)
  scan( db, '/')
  db.close()

  upload( 'image.xpi', server_address )

  os.unlink( 'image.xpi')

