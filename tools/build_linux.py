#!/usr/bin/env python2

import subprocess
import os
import sys

def execute(cmd):
  shell_cmd = 'sh -c "{}"'.format(' '.join(cmd))
  print('$ ' + shell_cmd)
  # return subprocess.check_call(shell_cmd, shell=True)

  process = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  # Poll process for new output until finished
  while True:
      nextline = process.stdout.readline()
      if nextline == '' and process.poll() is not None:
          break
      sys.stdout.write(nextline)
      sys.stdout.flush()

  return process.returncode

def run():
  DYNAMIC = 1 << 0
  SECURE = 1 << 1
  DEBUG = 1 << 2
  IPV4 = 1 << 3
  TCP = 1 << 4
  ret = 0

  for i in [DYNAMIC, SECURE, DEBUG, IPV4, TCP]:
    cmd = ['cd', '../port/linux', '&&']
    cmd.append('make')

    if i & DYNAMIC:
      cmd.append('DYNAMIC=0')
    else:
      cmd.append('DYNAMIC=1')

    if i & SECURE:
      cmd.append('SECURE=0')
    else:
      cmd.append('SECURE=1')

    if i & DEBUG:
      cmd.append('DEBUG=0')
    else:
      cmd.append('DEBUG=1')

    if i & IPV4:
      cmd.append('IPV4=0')
    else:
      cmd.append('IPV4=1')

    if i & TCP:
      cmd.append('TCP=0')
    else:
      cmd.append('TCP=1')

    print("====================================================")
    execute(['cd', '../port/linux', '&&', 'make', 'cleanall'])
    ret = execute(cmd)
    print("====================================================")
    if ret is not 0:
      print("=================BUILD ERROR OCCUR==================")
      break
  return ret

if __name__ == "__main__":
  if run() == 0:
    print("===================BUILD SUCCESS====================")