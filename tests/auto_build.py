#!/usr/bin/python

import os
import sys
import platform
import subprocess
import multiprocessing

# help message
def helpmsg(script):
    helpstr = '''
Usage:
    build:
        python %s <targetbuild>
        Allowed values for <target_build>: all, linux
    clean:
        python %s -c
    '''
    print (helpstr % (script, script))
    sys.exit(1)

def call_make(build_options, extra_option_str):
    """
    This function formats and runs a scons command
    Arguments:
    build_options    -- {Dictionary} build flags (keys) associated with values;
    extra_option_str -- {String} extra options to append to scons command
    """
    cmd_line = "make VERBOSE=" + VERBOSE
    for key in build_options:
        cmd_line += " " + key + "=" + str(build_options[key])

    cmd_line += " " + str(extra_option_str)

    if not EXEC_MODE:
        print ("Would run : " + cmd_line)
    else:
        print ("Running : " + cmd_line)
        sys.stdout.flush()
        exit_code = subprocess.Popen(cmd_line, shell=True).wait()
        if exit_code != 0:
            sys.exit(exit_code)

def build_all(flag, extra_option_str):
    if platform.system() == "Linux":
        build_linux(flag, extra_option_str)

def build_linux(flag, extra_option_str):
    print ("*********** Build for linux ************")
    build_options = {}
    call_make(build_options, extra_option_str)


# Main module starts here
if os.getenv("MAKEFLAGS", "") == "":
    os.environ["MAKEFLAGS"] = "-Q -j " + str(multiprocessing.cpu_count())

arg_num     = len(sys.argv)
script_name = sys.argv[0]

# May be overridden in user's shell
VERBOSE = os.getenv("VERBOSE", "1")
EXEC_MODE = os.getenv("EXEC_MODE", True)
if EXEC_MODE in ['false', 'False', '0']:
    EXEC_MODE = False


if arg_num == 1:
    build_all("true", "")

elif arg_num == 2:
    if str(sys.argv[1]) == '-c':
        build_all("true", "-c")

    elif str(sys.argv[1]) == "all":
        build_all("true", "")

    elif str(sys.argv[1]) == "linux":
        build_linux("true", "")

    else:
        helpmsg(script_name)
else:
        helpmsg(script_name)

print ("===================== done =====================")
