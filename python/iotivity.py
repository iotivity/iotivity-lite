
#############################
#
#    copyright 2021 Open Interconnect Consortium, Inc. All rights reserved.
#    Redistribution and use in source and binary forms, with or without modification,
#    are permitted provided that the following conditions are met:
#    1.  Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#    2.  Redistributions in binary form must reproduce the above copyright notice,
#        this list of conditions and the following disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
#    THIS SOFTWARE IS PROVIDED BY THE OPEN INTERCONNECT CONSORTIUM, INC. "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE OR
#    WARRANTIES OF NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL THE OPEN INTERCONNECT CONSORTIUM, INC. OR
#    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#    OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#    EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#############################


#sudo apt-get -y install python3-pip
#sudo pip3 install numpy
# 

import ctypes as c

import signal

import time
import os
import json
import random
import sys
import argparse
import traceback
from datetime import datetime
from time import gmtime, strftime
from sys import exit
#import jsonref
import os.path
from os import listdir
from os.path import isfile, join
from shutil import copyfile
from  collections import OrderedDict

import numpy.ctypeslib as ctl


import threading
import time


@c.CFUNCTYPE(c.c_int)
def init_callback():
    print("init_callback")
    return c.c_int(0)


@c.CFUNCTYPE(None)
def signal_event_loop():
    print("signal_event_loop")
    
  

  #int ret = oc_init_platform("OCF", NULL, NULL);
  #ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.2.2",
  #                     "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
  #oc_device_bind_resource_type(0, "oic.d.ams");
  #oc_device_bind_resource_type(0, "oic.d.cms");
  #return ret;

cb_type = c.CFUNCTYPE(c.c_int)

class HANDLER(c.Structure):
      #c_callback = c.CFUNCTYPE(c.c_int)
      
      _fields_ = [(".init",  c.CFUNCTYPE(c.c_int)),
                 (".signal_event_loop",  c.CFUNCTYPE(c.c_int)),
                 (".requests_entry",  c.CFUNCTYPE(None))]
                 
      _defaults_ = { ".init" : init_callback,
                     ".signal_event_loop": signal_event_loop,
                     ".requests_entry": None
                   }


@c.CFUNCTYPE(None, c.c_char * 37, c.c_void_p, c.c_void_p )
def unowned_device_cb(uuid, eps, data):
  PRINT("\nDiscovered unowned device: %s at:\n", di);
  

@c.CFUNCTYPE(None, c.c_char * 37, c.c_void_p, c.c_void_p )
def owned_device_cb(uuid, eps, data):
  PRINT("\nDiscovered owned device: %s at:\n", di);


class Iotivity():
    def __init__(self):
        print ("loading ...")
        libname = 'libiotivity-lite-client-python.so'
        libdir = './'
        self.lib=ctl.load_library(libname, libdir)
        
        
        # declare C function to be called from the shared library
#csum_block = cdll.LoadLibrary('./libcsum_block.so').csum_block
#csum_block.argtypes = [c_void_p, c_uint32]
#csum_block.restype = c_uint64
        
        
        print (self.lib)
        print ("...")
        

        #self.lib.oc_storage_config("./onboarding_tool_creds");

        #oc_set_factory_presets_cb(factory_presets_cb, NULL);
        self.lib.oc_set_con_res_announced(c.c_bool(False));
        print("oc_set_con_res_announced - done")
        self.lib.oc_set_max_app_data_size(c.c_size_t(16384));
        print("oc_set_max_app_data_size- done")
        value = self.lib.oc_get_max_app_data_size()
        print("oc_get_max_app_data_size :", value)
        print ("...")
        # old stuff
        #self.Handler_struct = HANDLER()
        #init = self.lib.oc_main_init(c.pointer(self.Handler_struct));
        
        #init = self.lib.python_main()
        #print (init)
        
        #self.threadid = threading.Thread(target=self.thread_function, args=(), daemon=True)
        self.threadid = threading.Thread(target=self.thread_function, args=())
    
        self.threadid.start()
        
        self.lib.test_print()
        
        print ("...")
        #self.init_platform()
        print ("...init_platform - done")
        
    def thread_function(self):
        print ("thread started")
        init = self.lib.python_main()
        

    def init_platform(self):
        #ret = self.lib.oc_storage_config(c.c_char_p("./onboarding_tool_creds"));
        ret = self.lib.oc_storage_config("./onboarding_tool_creds");
        print ("oc_storage_config-done", ret)
        ret = self.lib.oc_init_platform("OCF", None, None)
        print ("oc_init_platform-done", ret)
        ret = self.lib.oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.2.2", "ocf.res.1.0.0,ocf.sh.1.0.0", None, None)
        print ("oc_init_platform-done", ret)
        ret = self.lib.oc_device_bind_resource_type(0, "oic.d.ams")
        print ("oc_device_bind_resource_type-ams-done", ret)
        ret = self.lib.oc_device_bind_resource_type(0, "oic.d.cms")
        print ("oc_device_bind_resource_type-cms-done", ret)
        print("oc_init_platform-done",ret)
        self.lib.display_device_uuid();
        
    def discover_unowned(self):
        print(" discover_unowned ")
        ret = self.lib.discover_unowned_devices(c.c_int(0x02))
        ret = self.lib.discover_unowned_devices(c.c_int(0x03))
        ret = self.lib.discover_unowned_devices(c.c_int(0x05))
        
        #ret = self.lib.oc_obt_discover_unowned_devices(unowned_device_cb, None)
        print(" discover_unowned- done")
        
    def discover_owned(self):
        print(" discover_owned ")
        ret = self.lib.discover_owned_devices(c.c_int(0x02))
        ret = self.lib.discover_owned_devices(c.c_int(0x03))
        ret = self.lib.discover_owned_devices(c.c_int(0x05))
        
        #ret = self.lib.oc_obt_discover_owned_devices(owned_device_cb, None)
        print(" discover_owned- done")
        
        
    def quit(self):
        self.lib.python_exit(c.c_int(0))


    def sig_handler(self, signum, frame):
        print ("sig_handler..")
        self.quit()
        sys.exit()
        



my_iotivity = Iotivity()
signal.signal(signal.SIGINT, my_iotivity.sig_handler)

time.sleep(1)

my_iotivity.discover_unowned()
my_iotivity.discover_owned()

while True:
    time.sleep(5)
    
    









