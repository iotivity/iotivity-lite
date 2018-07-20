#!/usr/bin/python

import os
import sys
import subprocess

build_option_param = {
    "DYNAMIC": 1,
    "IPV4": 1,
    "TCP": 1,
    "EASYSETUP": 1,
    "ST_APP_FW": 1,
    "SECURE": 1
}

# help message
def helpmsg(script):
    helpstr = '''
Usage:
    build:
        python %s <targetbuild>
        Allowed values for <target_build>:
            linux,
            tizenrt,
            freertos
    clean:
        python %s -c
    '''
    print (helpstr % (script, script))
    sys.exit(1)

def execute_cmd(cmd):
    print ("Running : " + cmd.replace('&&', '&&\n'))
    sys.stdout.flush()
    exit_code = subprocess.Popen(cmd, shell=True).wait()
    if exit_code != 0:
        sys.exit(exit_code)

def call_make(build_options, extra_option_str):
    """
    This function formats and runs a scons command
    Arguments:
    build_options    -- {Dictionary} build flags (keys) associated with values;
    extra_option_str -- {String} extra options to append to scons command
    """
    cmd_line = "cd ../tests/ && make VERBOSE=1"
    for key in build_options:
        cmd_line += " " + key + "=" + str(build_options[key])

    cmd_line += " " + str(extra_option_str)
    execute_cmd(cmd_line)


def build_linux(extra_option_str):
    print ("*********** Build for linux ************")
    build_options = build_option_param
    call_make(build_options, extra_option_str)

def build_tizenrt(extra_option_str):
    print ("*********** Build for tizenrt ************")
    build_options = build_option_param
    extra_option_str += "port=tizenrt"
    call_make(build_options, extra_option_str)

def build_freertos(extra_option_str):
    print ("*********** Build for freertos ************")
    build_options = build_option_param
    extra_option_str += "port=freertos"
    call_make(build_options, extra_option_str)

def make_prebuilt(port):
    print ("*********** make pre-built lib ************")
    cmd_line = \
        "cd ../ && mkdir -p prebuilt && mkdir -p prebuilt/include && " \
        "mkdir -p prebuilt/include/deps/tinycbor/src && " \
        "mkdir -p prebuilt/include/util && " \
        "mkdir -p prebuilt/lib && " \
        "mkdir -p prebuilt/json && " \
        "cp port/%(port)s/config.h include/oc_helpers.h include/oc_rep.h " \
        "service/st-app-fw/include/st_manager.h service/st-app-fw/include/st_types.h " \
        "service/st-app-fw/include/st_resource_manager.h prebuilt/include && " \
        "cp service/st-app-fw/include/st_fota_manager.h service/fota/include/fota_types.h prebuilt/include && " \
        "cp deps/tinycbor/src/cbor.h deps/tinycbor/src/tinycbor-version.h prebuilt/include/deps/tinycbor/src && " \
        "cp util/oc_list.h util/oc_memb.h util/oc_mmem.h prebuilt/include/util && " \
        "cp port/%(port)s/libst-app-framework.a prebuilt/lib && " \
        "cp apps/st_app/json/* prebuilt/json && " \
        "cp apps/st_app/%(port)s/st_device_def.h prebuilt/include && " \
        "cp apps/st_app/%(port)s/st_ref_app.c apps/st_app/%(port)s/Makefile prebuilt/"
    execute_cmd(cmd_line % {'port': port})

def build_st_app():
    print ("*********** make st_app ************")
    cmd_line = "cd ../prebuilt && make"
    execute_cmd(cmd_line)

if __name__ == "__main__":
    arg_num     = len(sys.argv)
    script_name = sys.argv[0]

    print ("==================== start =====================")
    if arg_num is 2:
        if str(sys.argv[1]) == "linux":
            build_linux("")
        elif str(sys.argv[1]) == "tizenrt":
            build_tizenrt("")
        elif str(sys.argv[1]) == "freertos":
            build_freertos("")
        elif str(sys.argv[1]) == "-c":
            execute_cmd("rm -rf ../prebuilt")
            sys.exit(0)
        else:
            helpmsg(script_name)
            sys.exit(-1)

        make_prebuilt(sys.argv[1])
        build_st_app()
    else:
        helpmsg(script_name)
        sys.exit(-1)
    print ("===================== done =====================")
