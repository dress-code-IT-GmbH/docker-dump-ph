#!/usr/bin/python3

import os
import sys

cmd = '/opt/bin/dump.py'
arg = ['-c', '/var/data/dump.conf', '-o', '/var/data/data.ldif']
if os.environ.get ('DUMP_COMMAND', '') :
    cmds = os.environ ['DUMP_COMMAND'].split (' ')
    cmd  = cmds [0]
    arg  = cmds [1:]
if len (sys.argv) > 1 :
    cmd = sys.argv [1]
    arg = sys.argv [2:]
arg0 = os.path.basename (cmd)
os.execl (cmd, arg0, *arg)
