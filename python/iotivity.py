#############################
#
#    copyright 2021 Open Connectivity Forum, Inc. All rights reserved.
#    copyright 2021 Cascoda Ltd.
#    Redistribution and use in source and binary forms, with or without modification,
#    are permitted provided that the following conditions are met:
#    1.  Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#    2.  Redistributions in binary form must reproduce the above copyright notice,
#        this list of conditions and the following disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
#    THIS SOFTWARE IS PROVIDED BY THE OPEN CONNECTIVITY FORUM, INC. "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE OR
#    WARRANTIES OF NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL THE OPEN CONNECTIVITY FORUM, INC. OR
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
#

import ctypes, os, sys
from ctypes import *

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
from typing import List
from termcolor import colored

import numpy.ctypeslib as ctl

import uuid

import threading
import time

import json

import requests

import copy

unowned_return_list=[]

unowned_event = threading.Event()
owned_event = threading.Event()
resource_event = threading.Event()
diplomat_event = threading.Event()
so_event = threading.Event()
client_event = threading.Event()
device_event = threading.Event()
resource_mutex = threading.Lock()

ten_spaces = "          "

_int_types = (c_int16, c_int32)
if hasattr(ctypes, "c_int64"):
    # Some builds of ctypes apparently do not have c_int64
    # defined; it's a pretty good bet that these builds do not
    # have 64-bit pointers.
    _int_types += (c_int64,)
for t in _int_types:
    if sizeof(t) == sizeof(c_size_t):
        c_ptrdiff_t = t
del t
del _int_types


class UserString:
    def __init__(self, seq):
        if isinstance(seq, bytes):
            self.data = seq
        elif isinstance(seq, UserString):
            self.data = seq.data[:]
        else:
            self.data = str(seq).encode()

    def __bytes__(self):
        return self.data

    def __str__(self):
        return self.data.decode()

    def __repr__(self):
        return repr(self.data)

    def __int__(self):
        return int(self.data.decode())

    def __long__(self):
        return int(self.data.decode())

    def __float__(self):
        return float(self.data.decode())

    def __complex__(self):
        return complex(self.data.decode())

    def __hash__(self):
        return hash(self.data)

    def __cmp__(self, string):
        if isinstance(string, UserString):
            return cmp(self.data, string.data)
        else:
            return cmp(self.data, string)

    def __le__(self, string):
        if isinstance(string, UserString):
            return self.data <= string.data
        else:
            return self.data <= string

    def __lt__(self, string):
        if isinstance(string, UserString):
            return self.data < string.data
        else:
            return self.data < string

    def __ge__(self, string):
        if isinstance(string, UserString):
            return self.data >= string.data
        else:
            return self.data >= string

    def __gt__(self, string):
        if isinstance(string, UserString):
            return self.data > string.data
        else:
            return self.data > string

    def __eq__(self, string):
        if isinstance(string, UserString):
            return self.data == string.data
        else:
            return self.data == string

    def __ne__(self, string):
        if isinstance(string, UserString):
            return self.data != string.data
        else:
            return self.data != string

    def __contains__(self, char):
        return char in self.data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        return self.__class__(self.data[index])

    def __getslice__(self, start, end):
        start = max(start, 0)
        end = max(end, 0)
        return self.__class__(self.data[start:end])

    def __add__(self, other):
        if isinstance(other, UserString):
            return self.__class__(self.data + other.data)
        elif isinstance(other, bytes):
            return self.__class__(self.data + other)
        else:
            return self.__class__(self.data + str(other).encode())

    def __radd__(self, other):
        if isinstance(other, bytes):
            return self.__class__(other + self.data)
        else:
            return self.__class__(str(other).encode() + self.data)

    def __mul__(self, n):
        return self.__class__(self.data * n)

    __rmul__ = __mul__

    def __mod__(self, args):
        return self.__class__(self.data % args)

    # the following methods are defined in alphabetical order:
    def capitalize(self):
        return self.__class__(self.data.capitalize())

    def center(self, width, *args):
        return self.__class__(self.data.center(width, *args))

    def count(self, sub, start=0, end=sys.maxsize):
        return self.data.count(sub, start, end)

    def decode(self, encoding=None, errors=None):  # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.decode(encoding, errors))
            else:
                return self.__class__(self.data.decode(encoding))
        else:
            return self.__class__(self.data.decode())

    def encode(self, encoding=None, errors=None):  # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.encode(encoding, errors))
            else:
                return self.__class__(self.data.encode(encoding))
        else:
            return self.__class__(self.data.encode())

    def endswith(self, suffix, start=0, end=sys.maxsize):
        return self.data.endswith(suffix, start, end)

    def expandtabs(self, tabsize=8):
        return self.__class__(self.data.expandtabs(tabsize))

    def find(self, sub, start=0, end=sys.maxsize):
        return self.data.find(sub, start, end)

    def index(self, sub, start=0, end=sys.maxsize):
        return self.data.index(sub, start, end)

    def isalpha(self):
        return self.data.isalpha()

    def isalnum(self):
        return self.data.isalnum()

    def isdecimal(self):
        return self.data.isdecimal()

    def isdigit(self):
        return self.data.isdigit()

    def islower(self):
        return self.data.islower()

    def isnumeric(self):
        return self.data.isnumeric()

    def isspace(self):
        return self.data.isspace()

    def istitle(self):
        return self.data.istitle()

    def isupper(self):
        return self.data.isupper()

    def join(self, seq):
        return self.data.join(seq)

    def ljust(self, width, *args):
        return self.__class__(self.data.ljust(width, *args))

    def lower(self):
        return self.__class__(self.data.lower())

    def lstrip(self, chars=None):
        return self.__class__(self.data.lstrip(chars))

    def partition(self, sep):
        return self.data.partition(sep)

    def replace(self, old, new, maxsplit=-1):
        return self.__class__(self.data.replace(old, new, maxsplit))

    def rfind(self, sub, start=0, end=sys.maxsize):
        return self.data.rfind(sub, start, end)

    def rindex(self, sub, start=0, end=sys.maxsize):
        return self.data.rindex(sub, start, end)

    def rjust(self, width, *args):
        return self.__class__(self.data.rjust(width, *args))

    def rpartition(self, sep):
        return self.data.rpartition(sep)

    def rstrip(self, chars=None):
        return self.__class__(self.data.rstrip(chars))

    def split(self, sep=None, maxsplit=-1):
        return self.data.split(sep, maxsplit)

    def rsplit(self, sep=None, maxsplit=-1):
        return self.data.rsplit(sep, maxsplit)

    def splitlines(self, keepends=0):
        return self.data.splitlines(keepends)

    def startswith(self, prefix, start=0, end=sys.maxsize):
        return self.data.startswith(prefix, start, end)

    def strip(self, chars=None):
        return self.__class__(self.data.strip(chars))

    def swapcase(self):
        return self.__class__(self.data.swapcase())

    def title(self):
        return self.__class__(self.data.title())

    def translate(self, *args):
        return self.__class__(self.data.translate(*args))

    def upper(self):
        return self.__class__(self.data.upper())

    def zfill(self, width):
        return self.__class__(self.data.zfill(width))


class MutableString(UserString):
    """mutable string objects

    Python strings are immutable objects.  This has the advantage, that
    strings may be used as dictionary keys.  If this property isn't needed
    and you insist on changing string values in place instead, you may cheat
    and use MutableString.

    But the purpose of this class is an educational one: to prevent
    people from inventing their own mutable string class derived
    from UserString and than forget thereby to remove (override) the
    __hash__ method inherited from UserString.  This would lead to
    errors that would be very hard to track down.

    A faster and better solution is to rewrite your program using lists."""

    def __init__(self, string=""):
        self.data = string

    def __hash__(self):
        raise TypeError("unhashable type (it is mutable)")

    def __setitem__(self, index, sub):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data):
            raise IndexError
        self.data = self.data[:index] + sub + self.data[index + 1 :]

    def __delitem__(self, index):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data):
            raise IndexError
        self.data = self.data[:index] + self.data[index + 1 :]

    def __setslice__(self, start, end, sub):
        start = max(start, 0)
        end = max(end, 0)
        if isinstance(sub, UserString):
            self.data = self.data[:start] + sub.data + self.data[end:]
        elif isinstance(sub, bytes):
            self.data = self.data[:start] + sub + self.data[end:]
        else:
            self.data = self.data[:start] + str(sub).encode() + self.data[end:]

    def __delslice__(self, start, end):
        start = max(start, 0)
        end = max(end, 0)
        self.data = self.data[:start] + self.data[end:]

    def immutable(self):
        return UserString(self.data)

    def __iadd__(self, other):
        if isinstance(other, UserString):
            self.data += other.data
        elif isinstance(other, bytes):
            self.data += other
        else:
            self.data += str(other).encode()
        return self

    def __imul__(self, n):
        self.data *= n
        return self


class String(MutableString, Union):

    _fields_ = [("raw", POINTER(c_char)), ("data", c_char_p)]

    def __init__(self, obj=""):
        if isinstance(obj, (bytes, UserString)):
            self.data = bytes(obj)
        else:
            self.raw = obj

    def __len__(self):
        return self.data and len(self.data) or 0

    def from_param(cls, obj):
        # Convert None or 0
        if obj is None or obj == 0:
            return cls(POINTER(c_char)())

        # Convert from String
        elif isinstance(obj, String):
            return obj

        # Convert from bytes
        elif isinstance(obj, bytes):
            return cls(obj)

        # Convert from str
        elif isinstance(obj, str):
            return cls(obj.encode())

        # Convert from c_char_p
        elif isinstance(obj, c_char_p):
            return obj

        # Convert from POINTER(c_char)
        elif isinstance(obj, POINTER(c_char)):
            return obj

        # Convert from raw pointer
        elif isinstance(obj, int):
            return cls(cast(obj, POINTER(c_char)))

        # Convert from c_char array
        elif isinstance(obj, c_char * len(obj)):
            return obj

        # Convert from object
        else:
            return String.from_param(obj._as_parameter_)

    from_param = classmethod(from_param)


def ReturnString(obj, func=None, arguments=None):
    return String.from_param(obj)



@CFUNCTYPE(c_int)
def init_callback():
    print("init_callback")
    return c_int(0)


@CFUNCTYPE(None)
def signal_event_loop():
    print("signal_event_loop")
    

cb_type = CFUNCTYPE(c_int)

class HANDLER(Structure):
      _fields_ = [(".init",  CFUNCTYPE(c_int)),
                 (".signal_event_loop",  CFUNCTYPE(c_int)),
                 (".requests_entry",  CFUNCTYPE(None))]
                 
      _defaults_ = { ".init" : init_callback,
                     ".signal_event_loop": signal_event_loop,
                     ".requests_entry": None
                   }

def wrap_function(lib, funcname, restype, argtypes):
    """Simplify wrapping ctypes functions"""
    func = lib.__getattr__(funcname)
    func.restype = restype
    func.argtypes = argtypes
    return func


class OC_UUID(Structure):
      _fields_ = [("id",  c_uint8 * 16)]

class OC_DEVICE_HANDLE(Structure):
    pass

OC_DEVICE_HANDLE._fields_ = (
         ('uuid', OC_UUID),
         ('device_name', c_char * 64),
         ('next', POINTER(OC_DEVICE_HANDLE)),
     )

# python list of copied unowned/owned devices on the local network
#my_unowned_devices = []
#my_owned_devices = []

# python callback of a discovery call
#@CFUNCTYPE(None, POINTER(OC_UUID), c_void_p, c_void_p )
#def unowned_device_cb(uuid, eps, data):
#  print("\nDiscovered unowned device:")
#  my_uuid = my_iotivity.uuid2str(uuid)
#  print (" uuid:",my_uuid)
#  if my_uuid not in myunowned_devices:
#    my_unowned_devices.append(my_uuid)
  

# python callback of a discovery call
#@CFUNCTYPE(None, POINTER(OC_UUID), c_void_p, c_void_p )
#def owned_device_cb(uuid, eps, data):
#  print("\nDiscovered owned device: ")
#  my_uuid = my_iotivity.uuid2str(uuid)
#  print (" uuid:",my_uuid)
#  if my_uuid not in my_owned_devices:
#    my_owned_devices.append(my_uuid)


CHANGED_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p, c_char_p)
DIPLOMAT_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p, c_char_p,c_char_p,c_char_p,c_char_p)
RESOURCE_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p, c_char_p, c_char_p)
CLIENT_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p,c_char_p)


class Device():

    def __init__(self,uuid,owned_state=None,name="",resources=None,resource_array=None, credentials=None, last_event=None):
        self.uuid = uuid
        self.owned_state = owned_state
        self.name = name 
        self.credentials = credentials
        self.resource_array = []
        self.last_event = last_event 

class Diplomat():

    def __init__(self,uuid=None,owned_state=None,name="",observe_state=None,target_dict=None,last_event=None):
        self.uuid=uuid
        self.owned_state = owned_state
        self.name = name
        self.observe_state = observe_state
        self.target_cred = {}
        self.last_event = last_event

diplomat = Diplomat()

class Iotivity():
    """ ********************************
    Call back handles general task like device 
    discovery. 
    needs to be before _init_
    **********************************"""

    def changedCB(self,uuid,cb_state,cb_event):
        print("Changed event: Device: {}, State:{} Event:{}".format(uuid, cb_state,cb_event))
        name = ""
        if uuid != None:
            uuid = uuid.decode("utf-8")
            name = self.get_device_name(uuid)
        if cb_state !=  None:
            cb_state = cb_state.decode("utf-8")
        if cb_event !=  None:
            cb_event = cb_event.decode("utf-8")
        if(cb_state=="unowned"):
            print("Unowned Discovery Event:{}".format(uuid))
            dev = Device(uuid,owned_state=False,name=name,last_event=cb_event)
            if not self.device_array_contains(uuid):
                self.device_array.append(dev)
            if cb_event is not None: #update array entry
                for index, device in enumerate(self.device_array):
                    if device.uuid==uuid:
                        self.device_array[index] = dev
                        device_event.set()
            unowned_event.set()
        if(cb_state=="owned"):
            print("Owned Discovery Event:{}".format(uuid))
            dev = Device(uuid,owned_state=True,name=name)
            self.device_array.append(dev)
            owned_event.set()
    
    """ ********************************
    Call back handles streamlined onboarding tasks.
    Dipomat discovery/state
    Observes from diplomat
    **********************************"""
    def diplomatCB(self,anchor,uri,state,cb_event,target,target_cred):
        uuid = str(anchor)[8:-1]
        if len(uuid):
            diplomat.uuid = uuid
        if len(state):
            diplomat.owned_state = state
        if cb_event is not None:
            last_event = diplomat.last_event=cb_event.decode('utf-8').split(":",1) 
            if last_event[0] == "so_otm":
                so_event.set()
        diplomat_event.set()
        print("Diplomat CB: UUID: {}, Uri:{} State:{} Event:{} Target:{} Target Cred:{}".format(uuid,uri,state,cb_event,target,target_cred))

    """ ********************************
    Call back handles client command callbacks.
    Client discovery/state
    **********************************"""
    def clientCB(self,cb_uuid,cb_state,cb_event):
        uuid=""
        state=""
        event=""
        if len(cb_uuid):
            uuid =  cb_uuid.decode("utf-8")
        if len(cb_state):
            state = cb_state.decode("utf-8")
        if cb_event is not None:
            event = cb_event.decode("utf-8")
        print("Command CB: UUID: {}, State:{}, Event:{}".format(uuid,state,event))
    
    """ ********************************
    Call back handles resource call backs tasks.
    Resources is an dictionary with uuid of device
    **********************************"""
    def resourceCB(self, anchor, uri, rtypes, myjson):
        uuid = str(anchor)[8:-1]
        uuid_new = copy.deepcopy(uuid)
        my_uri = str(uri)[2:-1]

 
        if self.debug is not None and 'resources' in self.debug:
            print(colored("          Resource Event          \n",'green',attrs=['underline']))
            print(colored("UUID:{}, \nURI:{}",'green').format(uuid_new,my_uri))
        my_str = str(myjson)[2:-1]
        my_str = json.loads(my_str)
        
        duplicate_uri = False

        if self.resourcelist.get(uuid_new) is None:
            mylist = [ my_str ]
            #don't add duplicate rsources lists
            if uuid_new not in self.resourcelist:
                self.resourcelist[uuid_new] = mylist
        else:
            mylist = self.resourcelist[uuid_new]
            #Make sure to not add duplicate resources if second discovery
            for resource in mylist:
                if my_uri == resource['uri']:
                    duplicate_uri=True
            if not duplicate_uri:
                mylist.append(my_str)
            #don't add duplicate rsources lists
            if uuid_new not in self.resourcelist:
                self.resourcelist[uuid_new] = mylist
        if self.debug is not None and 'resources' in self.debug:
            print(colored(" -----resourcelist {}",'cyan').format(mylist))

        #Look for zero length uri...this means discovery is complete
        if len(my_uri) <=0:
            resource_event.set()
            print("ALL resources gathered");
        if self.debug is not None and 'resources' in self.debug:
            print(colored("Resources {}",'yellow').format(self.resourcelist))


    def __init__(self,debug=None):
        print ("loading ...")
        resource_mutex.acquire()
        libname = 'libiotivity-lite-client-python.so'
        libdir = os.path.dirname(__file__) 
        self.lib=ctl.load_library(libname, libdir)
        # python list of copied unowned devices on the local network
        # will be updated from the C layer automatically by the CHANGED_CALLBACK
        self.unowned_devices = []
        # python list of copied owned devices on the local network
        # will be updated from the C layer automatically by the CHANGED_CALLBACK
        self.owned_devices = []
        # resource list
        self.resourcelist = {}

        self.device_array = []
        print (self.lib)
        print ("...")
        self.debug=debug
        self.lib.oc_set_con_res_announced(c_bool(False));
        print("oc_set_con_res_announced - done")
        self.lib.oc_set_max_app_data_size(c_size_t(16384));
        print("oc_set_max_app_data_size- done")
        value = self.lib.oc_get_max_app_data_size()
        print("oc_get_max_app_data_size :", value)
        self.changedCB = CHANGED_CALLBACK(self.changedCB)
        self.lib.install_changedCB(self.changedCB)
        ret = self.lib.oc_storage_config("./onboarding_tool_creds");
        print("oc_storage_config : {}".format(ret))

        self.resourceCB = RESOURCE_CALLBACK(self.resourceCB)
        self.lib.install_resourceCB(self.resourceCB)
        
        self.diplomatCB = DIPLOMAT_CALLBACK(self.diplomatCB)
        self.lib.install_diplomatCB(self.diplomatCB)

        self.clientCB = CLIENT_CALLBACK(self.clientCB)
        self.lib.install_diplomatCB(self.clientCB)

        print ("...")
        self.threadid = threading.Thread(target=self.thread_function, args=())  
        self.threadid.start()
        print ("...")
        
    def thread_function(self):
        """ starts the main function in C.
        this function is threaded in python.
        """
        print ("thread started")
        init = self.lib.python_main()
        
    def init_platform(self):
        # not used
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
        #self.lib.display_device_uuid();
    
    def get_result(self): 
        self.lib.get_cb_result.restype = bool
        return self.lib.get_cb_result()
    
    def get_response_payload(self): 
        self.lib.get_response_payload.restype = String
        return self.lib.get_response_payload()


    def purge_device_array(self,uuid):
        for index, device in enumerate(self.device_array):
            if device.uuid==uuid:
                print("Remove: {}".format(device.uuid))
                self.device_array.pop(index)
        
    def discover_unowned(self):
        print(colored(20*" "+"Discover Unowned Devices"+20*" ",'yellow',attrs=['underline']))
        # OBT application
        ret = self.lib.discover_unowned_devices(c_int(0x05))
        time.sleep(3)
        # python callback application
        print("discover_unowned- done")
        nr_unowned = self.get_nr_unowned_devices()
        owned_state=False
        #self.purge_device_array(owned_state)
        unowned_event.wait(5)
        print("UNOWNED DEVICE ARRAY {}".format(self.device_array))
        return self.device_array

    def device_array_contains(self,uuid):
        contains = False
        for index, device in enumerate(self.device_array):
            if device.uuid == uuid:
                contains = True
        return contains 

    def get_device(self,uuid):
        ret = None
        for index, device in enumerate(self.device_array):
            if device.uuid == uuid:
                ret = device
        return ret 

    def return_devices_array(self):
        return self.device_array

    def discover_all(self):
        self.discover_unowned()
        self.discover_owned()
        time.sleep(20)
        self.list_owned_devices()
        self.list_unowned_devices()


    def return_unowned_devices(self):
        print("Called return list Thread:{}".format(threading.get_ident()))
        unowned_return_list={}
        nr_unowned = self.get_nr_unowned_devices()
        for i in range(nr_unowned):
            uuid = self.get_unowned_uuid(i)+""
            unowned_return_list[i] = uuid
        return unowned_return_list
        
    def list_unowned_devices(self):
        nr_unowned = self.get_nr_unowned_devices()
        print ("list_unowned_devices: unowned:",nr_unowned )
        for i in range(nr_unowned):
            uuid = self.get_unowned_uuid(i)
            print ("  unowned index {} uuid {}".format(i, uuid))
            if uuid not in self.unowned_devices:
              self.unowned_devices.append(uuid)

    def list_owned_devices(self):
        nr_owned = self.get_nr_owned_devices()
        print ("list_owned_devices: owned:",nr_owned )
        for i in range(nr_owned):
            uuid = self.get_owned_uuid(i)
            print ("  owned index {} uuid {}".format(i, uuid))
            if uuid not in self.owned_devices:
              self.owned_devices.append(uuid)


    def discover_owned(self):
        print(colored(20*" "+"Discover Owned Devices"+20*" ",'yellow',attrs=['underline']))
        #ret = self.lib.discover_owned_devices(c_int(0x02))
        #ret = self.lib.discover_owned_devices(c_int(0x03))
        ret = self.lib.discover_owned_devices(c_int(0x05))
        time.sleep(3)
        # call with call back in python
        #ret = self.lib.oc_obt_discover_owned_devices(owned_device_cb, None)
        nr_owned = self.get_nr_owned_devices()
        owned_state=True
        owned_event.wait(5)
        print("OWNED DEVICE ARRAY {}",self.device_array)
        return self.device_array

    def discover_diplomats(self):
        print(colored(20*" "+"Discover Diplomats"+20*" ",'yellow',attrs=['underline']))
        ret = self.lib.py_discover_diplomat_for_observe();
        diplomat_event.wait(5)
        return diplomat 

    def diplomat_set_observe(self,state):
        state = copy.deepcopy(state)
        print(colored(20*" "+"Set Diplomats"+20*" ",'yellow',attrs=['underline']))
        print("Diplomat State: {}".format(state))
        self.lib.py_diplomat_set_observe.argtypes = [String]
        ret = self.lib.py_diplomat_set_observe(str(state))
        print("Waiting for Streamlined OTM ")
        so_event.wait()
        return diplomat

    def quit(self):
        self.lib.python_exit(c_int(0))

    def sig_handler(self, signum, frame):
        print ("sig_handler..")
        self.offboard_all_owned()
        time.sleep(10)
        self.quit()
        sys.exit()

    def uuid2str(self, oc_uuid):
        print (" uuid in:", oc_uuid)
        my_uuid = create_string_buffer(50)
        self.lib.oc_uuid_to_str.argstype = [ POINTER(OC_UUID), c_char_p, c_int]
        self.lib.oc_uuid_to_str(oc_uuid, my_uuid, 50)
        return str(my_uuid.value)

    def str2uuid(self, my_uuid):
        self.lib.oc_uuid_to_str.argtypes = [c_char_p, POINTER(OC_UUID)]
        my_uuid_s = OC_UUID()
        my_uuid_bytes = str(my_uuid).encode('utf-8')
        self.lib.oc_uuid_to_str(my_uuid_bytes, my_uuid_s)
        print ("  type: ", my_uuid_s)
        return my_uuid_s
    
    def test_uuid(self):
        my_uuid = str(uuid.uuid4())
        print ("uuid in :", my_uuid)
        my_s = self.str2uuid(my_uuid)
        r_uuid = self.uuid2str(my_s)
        print (" returned:", r_uuid)

    def get_nr_owned_devices(self):
        # retrieves the owned nr owned devices of the IoTivity layer
        # note that a discovery request has to be executed before this call
        self.lib.py_get_nr_owned_devices.argtypes = []
        self.lib.py_get_nr_owned_devices.restype = c_int
        return self.lib.py_get_nr_owned_devices()

    def get_nr_unowned_devices(self):
        # retrieves the owned nr unowned devices of the IoTivity layer
        # note that a discovery request has to be executed before this call
        self.lib.py_get_nr_unowned_devices.argtypes = []
        self.lib.py_get_nr_unowned_devices.restype = c_int
        return self.lib.py_get_nr_unowned_devices()
    
    def get_owned_uuid(self, index):
        # retrieves the uuid of the owned device
        # index of owned list of devices in IoTivity layer
        self.lib.get_uuid.argtypes = [c_int, c_int]
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_uuid.restype = ReturnString
        else:
            self.lib.get_uuid.restype = String
            self.lib.get_uuid.errcheck = ReturnString
        uuid = self.lib.get_uuid(1,c_int(index))
        uuid_copy = '' + uuid
        return uuid_copy

    def get_unowned_uuid(self, index):
        # retrieves the uuid of the unowned device
        # index of unowned list of devices in IoTivity layer
        self.lib.get_uuid.argtypes = [c_int, c_int]
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_uuid.restype = ReturnString
        else:
            self.lib.get_uuid.restype = String
            self.lib.get_uuid.errcheck = ReturnString
        uuid  = self.lib.get_uuid(0,c_int(index))
        uuid_copy = '' + uuid
        print ("get_unowned_uuid: uuid:", uuid) 
        return uuid_copy


    def get_owned_device_name(self, index):
        # retrieves the uuid of the owned device
        # index of owned list of devices in IoTivity layer
        self.lib.get_device_name.argtypes = [c_int, c_int]
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_device_name.restype = ReturnString
        else:
            self.lib.get_uget_device_nameuid.restype = String
            self.lib.get_device_name.errcheck = ReturnString
        return self.lib.get_device_name(1,c_int(index))

    def get_unowned_device_name(self, index):
        # retrieves the uuid of the unowned device
        # index of unowned list of devices in IoTivity layer
        self.lib.get_device_name.argtypes = [c_int, c_int]
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_device_name.restype = ReturnString
        else:
            self.lib.get_device_name.restype = String
            self.lib.get_uuid.errcheck = ReturnString
        device_name  = self.lib.get_device_name(0,c_int(index))
        print("Device Name: {}, {}".format(device_name,index))
        return device_name

    def get_device_name(self, device_uuid):
        # retrieves the uuid of the owned device
        # index of owned list of devices in IoTivity layer
        self.lib.get_device_name_from_uuid.argtypes = [String]
        device_name = ""
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_device_name_from_uuid.restype = ReturnString
        else:
            self.lib.get_device_name_from_uuid.restype = String
            self.lib.get_device_name_from_uuid.errcheck = ReturnString
        device_name = self.lib.get_device_name_from_uuid(device_uuid)
        print("Device Name: {}".format(device_name))
        return str(device_name)


    def onboard_all_unowned(self):
        print ("onboard_all_unowned: listing NOT onboarded devices in C:")
        self.list_unowned_devices()

        print ("onboarding...")
        self.lib.py_otm_just_works.argtypes = [String]
        self.lib.py_otm_just_works.restype = None

        onboarded_devices = []

        for device in self.unowned_devices:
            device_name = self.get_device_name(device)
            print ("Onboarding device :", device, device_name)

            run_count = 0
            result = False
            while run_count < 5 and not result: 
                run_count += 1
                self.lib.py_otm_just_works(device)

                start_time = time.time()
                timeout = 10
                time.sleep(1)
                while True: 
                    result = self.get_result()
                    end_time = time.time()
                    if result or end_time > start_time + timeout: 
                        time_taken = end_time - start_time
                        break

            if result: 
                print (f"Onboarding succeeded for: {device} {device_name}")
                print (f"Time taken: {time_taken:.3} seconds")

                onboarded_devices.append(device)
            else: 
                print (f"Onboarding failed for: {device} {device_name}")
            time.sleep(1)
        
        for device in onboarded_devices: 
            self.unowned_devices.remove(device)

        print ("...done.")

    def onboard_cloud_proxy(self):
        print ("onboard_cloud_proxy: listing NOT onboarded devices in C:")
        self.list_unowned_devices()

        print ("onboarding...")
        self.lib.py_otm_just_works.argtypes = [String]
        self.lib.py_otm_just_works.restype = None

        onboarded_devices = []

        for device in self.unowned_devices:
            device_name = self.get_device_name(device)

            if "proxy" in str(device_name).lower(): 
                print ("Onboarding device :", device, device_name)

                run_count = 0
                result = False
                while run_count < 5 and not result: 
                    run_count += 1
                    self.lib.py_otm_just_works(device)

                    start_time = time.time()
                    timeout = 10
                    time.sleep(1)
                    while True: 
                        result = self.get_result()
                        end_time = time.time()
                        if result or end_time > start_time + timeout: 
                            time_taken = end_time - start_time
                            break

                if result: 
                    print (f"Onboarding succeeded for: {device} {device_name}")
                    print (f"Time taken: {time_taken:.3} seconds")

                    onboarded_devices.append(device)
                else: 
                    print (f"Onboarding failed for: {device} {device_name}")
                time.sleep(1)
        
        for device in onboarded_devices: 
            self.unowned_devices.remove(device)

        print ("...done.")

    def onboard_chili(self):
        print ("onboard_chili: listing NOT onboarded devices in C:")
        self.list_unowned_devices()

        print ("onboarding...")
        self.lib.py_otm_just_works.argtypes = [String]
        self.lib.py_otm_just_works.restype = None

        onboarded_devices = []

        for device in self.unowned_devices:
            device_name = self.get_device_name(device)

            if "cascoda" in str(device_name).lower(): 
                print ("Onboarding device :", device, device_name)

                run_count = 0
                result = False
                while run_count < 5 and not result: 
                    run_count += 1
                    self.lib.py_otm_just_works(device)

                    start_time = time.time()
                    timeout = 10
                    time.sleep(1)
                    while True: 
                        result = self.get_result()
                        end_time = time.time()
                        if result or end_time > start_time + timeout: 
                            time_taken = end_time - start_time
                            break

                if result: 
                    print (f"Onboarding succeeded for: {device} {device_name}")
                    print (f"Time taken: {time_taken:.3} seconds")

                    onboarded_devices.append(device)
                else: 
                    print (f"Onboarding failed for: {device} {device_name}")
                time.sleep(1)
        
        for device in onboarded_devices: 
            self.unowned_devices.remove(device)

        print ("...done.")


    def onboard_device(self,device):
        print("Onboarding device: {}".format(device))
        if device.otm == "justworks":
            self.lib.py_otm_just_works.argtypes = [String]
            self.lib.py_otm_just_works.restype = None
            self.lib.py_otm_just_works(device.uuid)
        if device.otm == "randompin":
            self.lib.py_otm_rdp.argtypes = [String, String]
            self.lib.py_otm_rdp.restype = None
            self.lib.py_otm_rdp(device.uuid,device.random_pin)

        #remove unowned uuid form resource list
        for key in self.resourcelist.keys():
            if key == device.uuid:
                del self.resourcelist[device.uuid]
                break
        self.purge_device_array(device.uuid)
    
    def request_random_pin(self,device):
        device_event.clear()
        print("Request Random PIN: {}".format(device))
        self.lib.py_request_random_pin.argtypes = [String]
        self.lib.py_request_random_pin.restype = None
        self.lib.py_request_random_pin(device.uuid)
        device_event.wait(5)
        ret =""
        for index, device_a in enumerate(self.device_array):
            print("uuid:{}, last_event:{}".format(device_a.uuid,device_a.last_event))
            if device_a.uuid==device.uuid:
                ret = device_a
                
        return ret 

    def offboard_device(self,device):
        print ("offboard device :", device)
        self.lib.py_reset_device.argtypes = [String]
        self.lib.py_reset_device.restype = None
        self.lib.py_reset_device(device)
        
        #remove owned uuid form resource list
        for key in self.resourcelist.keys():
            if key == device:
                del self.resourcelist[device]
                break
        self.purge_device_array(device)
    
    def offboard_all_owned(self):
        print ("listing onboarded devices:")
        self.list_owned_devices()

        print ("offboarding...")
        self.lib.py_reset_device.argtypes = [String]
        self.lib.py_reset_device.restype = None

        offboarded_devices = []

        for device in self.owned_devices:
            device_name = self.get_device_name(device)

            print ("Offboarding device :", device, device_name)

            run_count = 0
            result = False
            while run_count < 5 and not result: 
                run_count += 1
                self.lib.py_reset_device(device)

                start_time = time.time()
                timeout = 10
                time.sleep(1)
                while True: 
                    result = self.get_result()
                    end_time = time.time()
                    if result or end_time > start_time + timeout: 
                        time_taken = end_time - start_time
                        break

            if result: 
                print (f"Offboarding succeeded for: {device} {device_name}")
                print (f"Time taken: {time_taken:.3} seconds")

                offboarded_devices.append(device)
            else: 
                print (f"Offboarding failed for: {device} {device_name}")
            time.sleep(1)

        for device in offboarded_devices: 
            self.owned_devices.remove(device)

        print ("...done.")


    def provision_ace_cloud_access(self, device_uuid):
        self.lib.py_provision_ace_cloud_access.argtypes = [String]
        self.lib.py_provision_ace_cloud_access.restype = None

        device_name = self.get_device_name(device_uuid)
        print( "provision_ace_cloud_access (ACL):",device_uuid)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_ace_cloud_access(device_uuid)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break

        if result: 
            print (f"Provisioning ACE cloud access succeeded for: {device_uuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning ACE cloud access failed for: {device_uuid} {device_name}")
        time.sleep(1)

    def provision_ace_d2dserverlist(self, device_uuid): 
        self.lib.py_provision_ace_cloud_access.argtypes = [String]
        self.lib.py_provision_ace_cloud_access.restype = None

        device_name = self.get_device_name(device_uuid)
        print( "provision_ace_d2dserverlist (ACL):",device_uuid)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_ace_d2dserverlist(device_uuid)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break

        if result: 
            print (f"Provisioning ACE /d2dserverlist succeeded for: {device_uuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning ACE /d2dserverlist failed for: {device_uuid} {device_name}")
        time.sleep(1)

    def provision_ace_device_resources(self, chili_uuid, cloud_proxy_uuid): 
        # Grant cloud_proxy (aka subject) access to all Chili resources
        self.lib.py_provision_ace_device_resources.argtypes = [String, String]
        self.lib.py_provision_ace_device_resources.restype = None
        self.lib.py_provision_ace_device_resources(chili_uuid, cloud_proxy_uuid)

        chili_name = self.get_device_name(chili_uuid)
        cloud_proxy_name = self.get_device_name(cloud_proxy_uuid)
        print (f"py_provision_ace_device_resources (ACL) for: {chili_uuid} {chili_name}")
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_ace_device_resources(chili_uuid, cloud_proxy_uuid)

            start_time = time.time()
            timeout = 30
            time.sleep(3)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Provisioning ACE device resources (ACL) succeeded for: {chili_uuid} {chili_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning ACE device resources (ACL) failed for: {chili_uuid} {chili_name}")
        time.sleep(3)
        print ("...done.")


    def provision_pairwise(self, device1_uuid, device2_uuid):
        self.lib.py_provision_pairwise_credentials.argtypes = [String, String]
        self.lib.py_provision_pairwise_credentials.restype = None
        self.lib.py_provision_pairwise_credentials(str(device1_uuid),str(device2_uuid))

    def provision_ace(self, target_uuid, subject_uuid, href, crudn):
        self.lib.py_provision_ace2.argtypes = [String, String, String, String]
        self.lib.py_provision_ace2.restype = None
        self.lib.py_provision_ace2(target_uuid,subject_uuid,href,crudn)

    def provision_ace_cloud_access(self, device_uuid):
        self.lib.py_provision_ace_cloud_access.argtypes = [String]
        self.lib.py_provision_ace_cloud_access.restype = None
        print( "provision_ace_cloud_access (ACL):",device_uuid)
        self.lib.py_provision_ace_cloud_access(device_uuid)

    def provision_ace_all(self):
        print ("provision_ace_all....")
        for device in self.owned_devices:
            self.provision_ace_cloud_access(device)
        print ("provision_ace_all...done.")

    def provision_ace_cloud_proxy(self, cloud_proxy_uuid):
        print ("provision_ace_cloud_proxy....")
        self.provision_ace_cloud_access(cloud_proxy_uuid)
        self.provision_ace_d2dserverlist(cloud_proxy_uuid)
        print ("provision_ace_cloud_proxy...done.")

    def provision_ace_chili(self, chili_uuid, cloud_proxy_uuid):
        print ("provision_ace_chili....")
        self.provision_ace_device_resources(chili_uuid, cloud_proxy_uuid)
        print ("provision_ace_chili...done.")
    
    def provision_id_cert(self, device_uuid):
        self.lib.py_provision_id_cert.argtypes = [String]
        self.lib.py_provision_id_cert.restype = None

        device_name = self.get_device_name(device_uuid)
        print( "py_provision_id_cert:", device_uuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_id_cert(device_uuid)

            start_time = time.time()
            timeout = 20
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Provisioning id certs succeeded for: {device_uuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning id certs failed for: {device_uuid} {device_name}")
        time.sleep(1)

    def provision_id_cert_all(self):
        print ("provision_id_cert_all....")
        for device in self.owned_devices:
            self.provision_id_cert(device)
        print ("provision_id_cert_all...done.")

    def provision_role_cert(self, uuid, role, auth):
        self.lib.py_provision_role_cert.argtypes = [String, String, String]
        self.lib.py_provision_role_cert.restype = None
        self.lib.py_provision_role_cert(uuid, role, auth)

    def discover_resources(self, myuuid):
        self.lib.py_discover_resources.argtypes = [String]
        self.lib.py_discover_resources.restype = None
        
        device_name = self.get_device_name(myuuid)
        print( "py_discover_resources:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_discover_resources(myuuid)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Resource discovery succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Resource discovery failed for: {myuuid} {device_name}")
        time.sleep(1)
        try:
            ret = {myuuid:self.resourcelist[myuuid]}
            print("RET:{}".format(ret))
            return ret 
        except Exception as e:
            print("Exception: {} Re-trying resource discovery".format(e))

    def retrieve_acl2(self, myuuid): 
        self.lib.py_retrieve_acl2.argtypes = [String]
        self.lib.py_retrieve_acl2.restype = None
        
        device_name = self.get_device_name(myuuid)
        print( "py_retrieve_acl2:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_retrieve_acl2(myuuid)

            start_time = time.time()
            timeout = 15
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Retrieving ACL2 succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Retrieving ACL2 failed for: {myuuid} {device_name}")
        time.sleep(1)

    def provision_cloud_trust_anchor(self, myuuid, cloud_id, cloud_trust_anchor): 
        self.lib.py_provision_cloud_trust_anchor.argtypes = [String, String, String]
        self.lib.py_provision_cloud_trust_anchor.restype = None

        device_name = self.get_device_name(myuuid)
        print( "py_provision_cloud_trust_anchor:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_cloud_trust_anchor(myuuid, cloud_id, cloud_trust_anchor)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Provisioning cloud trust anchor succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning cloud trust anchor failed for: {myuuid} {device_name}")
        time.sleep(1)

    def provision_cloud_config_info(self, myuuid, cloud_access_token, cloud_apn, cloud_cis, cloud_id): 
        self.lib.py_provision_cloud_config_info.argtypes = [String, String, String, String, String]
        self.lib.py_provision_cloud_config_info.restype = None

        device_name = self.get_device_name(myuuid)
        print( "py_provision_cloud_config_info:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_provision_cloud_config_info(myuuid, cloud_access_token, cloud_apn, cloud_cis, cloud_id)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Provisioning cloud config info succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Provisioning cloud config info failed for: {myuuid} {device_name}")
        time.sleep(10)

    def retrieve_d2dserverlist(self, myuuid): 
        self.lib.py_retrieve_d2dserverlist.argtypes = [String]
        self.lib.py_retrieve_d2dserverlist.restype = None

        device_name = self.get_device_name(myuuid)
        print( "py_retrieve_d2dserverlist:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_retrieve_d2dserverlist(myuuid)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Retrieving /d2dserverlist succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Retrieving /d2dserverlist failed for: {myuuid} {device_name}")
        time.sleep(1)

    def post_d2dserverlist(self, myuuid, query): 
        self.lib.py_post_d2dserverlist.argtypes = [String, String]
        self.lib.py_post_d2dserverlist.restype = None

        device_name = self.get_device_name(myuuid)
        print( "py_post_d2dserverlist:", myuuid, device_name)
        
        run_count = 0
        result = False
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_post_d2dserverlist(myuuid, query)

            start_time = time.time()
            timeout = 20
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            print (f"Posting /d2dserverlist succeeded for: {myuuid} {device_name}")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Posting /d2dserverlist failed for: {myuuid} {device_name}")
        time.sleep(1)

    def general_get(self, uuid, url): 
        self.lib.py_general_get.argtypes = [String, String]
        self.lib.py_general_get.restype = None

        run_count = 0
        result = False
        response_payload = ""
        while run_count < 5 and not result: 
            run_count += 1
            self.lib.py_general_get(uuid, url)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            response_payload = self.get_response_payload()
            print (f"Sending GET request succeeded")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Sending GET request failed")
        time.sleep(1)
        return result, response_payload

    def general_post(self, uuid, query, url, payload_properties, payload_values, payload_types): 
        self.lib.py_general_post.argtypes = [String, String, String, POINTER(c_char_p), POINTER(c_char_p), POINTER(c_char_p), c_int]
        self.lib.py_general_post.restype = None

        list_size = len(payload_properties)
        for i in range(list_size): 
            payload_properties[i] = c_char_p(payload_properties[i].encode())
        for i in range(list_size): 
            payload_values[i] = c_char_p(payload_values[i].encode())
        for i in range(list_size): 
            payload_types[i] = c_char_p(payload_types[i].encode())

        properties_ptr = (c_char_p * len(payload_properties))(*payload_properties)
        values_ptr = (c_char_p * len(payload_values))(*payload_values)
        types_ptr = (c_char_p * len(payload_types))(*payload_types)

        run_count = 0
        result = False
        response_payload = ""
        while run_count < 5 and not result: 
            run_count += 1

            self.lib.py_general_post(uuid, query, url, properties_ptr, values_ptr, types_ptr, list_size)

            start_time = time.time()
            timeout = 10
            time.sleep(1)
            while True: 
                result = self.get_result()
                end_time = time.time()
                if result or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
        if result: 
            response_payload = self.get_response_payload()
            print (f"Sending POST request succeeded")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Sending POST request failed")
        time.sleep(1)
        return result, response_payload

    def get_idd(self, myuuid):
        print("get_idd ", myuuid)
        self.discover_resources(myuuid)
        time.sleep(3)

    def get_obt_uuid(self):
        self.lib.py_get_obt_uuid.restype = String
        obt_uuid = self.lib.py_get_obt_uuid()
        return str(obt_uuid)

        
        #resources = self.resourcelist.get(myuuid)
        print("get_idd ", self.resourcelist)
        #resources = self.resourcelist.get(myuuid)
        print("resources :", isinstance(self.resourcelist, dict))
        for l_uuid, value in self.resourcelist.items():
                print(" uuid in list", l_uuid)
                if l_uuid == myuuid:
                    print ("    ", value)  
        

    def my_sleep(self):
        while True:
            time.sleep(3)

    def request_plgd_AC(self): 
        """
        Send HTTP request to retrieve plgd cloud authorization code (AC)\n
        Which is required to connect devices to the cloud\n
        """

        # Request headers
        headers = {}
        with open("plgd_headers.config", "r") as f: 
            lines = f.read().splitlines()
            for line in lines: 
                (key, value) = line.split(": ", 1)
                headers[key] = value

        # Destination url
        url = 'https://auth.plgd.cloud/authorize?response_type=code&client_id=cYN3p6lwNcNlOvvUhz55KvDZLQbJeDr5&scope=offline_access&audience=https://try.plgd.cloud&redirect_uri=https://cloud.cascoda.com/things&device_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

        # Send request
        r = requests.get(url, verify=False, allow_redirects=False, headers=headers, timeout=3)

        # Handle response
        hd = dict(r.headers)

        # Extract AC
        location = hd['Location']

        AC_pos = location.find('code=')
        AC = location[AC_pos + 5:]
        print("Authorization Code (AC)=" + AC)

        # Extract auth0 cookie for next request
        set_cookie = hd['Set-Cookie']

        auth0_start = set_cookie.find('auth0=')
        auth0_end = set_cookie.find(';', auth0_start)
        auth0 = set_cookie[auth0_start: auth0_end]
        print(auth0)

        # Save auth0 cookie in this script
        with open('plgd_headers.config', 'r+') as f: 
            content = f.read()
            f.seek(0)

            auth0_original_start = content.find('auth0=')
            auth0_original_end = content.find(';', auth0_original_start)

            content = content[: auth0_original_start] + auth0 + content[auth0_original_end:]

            f.write(content)
            f.truncate()

        return AC

    def plgd_cloud_conf_download(self, url): 
        cloud_configurations = dict.fromkeys(["cloud_id", "cloud_trust_anchor", "cloud_apn", "cloud_cis", "cloud_access_token"])

        r = requests.get(url, verify=False, timeout=5)
        content = r.json()

        if "cascoda" in url: 
            cloud_configurations["cloud_id"] = content["id"]
            cloud_configurations["cloud_trust_anchor"] = content["certificateAuthorities"]
            cloud_configurations["cloud_apn"] = "plgd.web"
            cloud_configurations["cloud_cis"] = content["coapGateway"]
            cloud_configurations["cloud_access_token"] = self.request_plgd_AC()
        else: 
            cloud_configurations["cloud_id"] = content["cloudId"]
            cloud_configurations["cloud_trust_anchor"] = content["cloudCertificateAuthorities"]
            cloud_configurations["cloud_apn"] = content["cloudAuthorizationProvider"]
            cloud_configurations["cloud_cis"] = content["cloudUrl"]
            cloud_configurations["cloud_access_token"] = "test"
        
        return cloud_configurations

    def test_cascoda(self):
        very_start_time = time.time()
        expected_devices = 1

        try: 
            url = "https://192.168.202.112:8443/.well-known/cloud-configuration"
            cloud_configurations = self.plgd_cloud_conf_download(url) # To do: Make url configurable
        except: 
            url = "https://cloud.cascoda.com/.well-known/hub-configuration"
            cloud_configurations = self.plgd_cloud_conf_download(url)

        run_count = 0
        nr_owned = 0
        while run_count < 5 and nr_owned < expected_devices: 
            run_count += 1

            start_time = time.time()
            timeout = 20

            self.discover_all()

            self.onboard_cloud_proxy()

            self.onboard_chili()

            time.sleep(1)
            while True: 
                nr_owned = self.get_nr_owned_devices()
                end_time = time.time()
                if nr_owned >= expected_devices or end_time > start_time + timeout: 
                    time_taken = end_time - start_time
                    break
            time.sleep(1)

        if nr_owned >= expected_devices: 
            print (f"Discovery and onboarding succeeded, {nr_owned}/{expected_devices} devices onboarded")
            print (f"Time taken: {time_taken:.3} seconds")
        else: 
            print (f"Discovery and onboarding failed, {nr_owned}/{expected_devices} devices onboarded")
            self.offboard_all_owned()
            time.sleep(3)
            sys.exit(1)

        self.list_owned_devices()

        self.provision_id_cert_all()

        cloud_proxy_uuid = self.get_owned_uuid(0)

        self.provision_ace_cloud_proxy(cloud_proxy_uuid)

        self.discover_resources(cloud_proxy_uuid)

        self.retrieve_acl2(cloud_proxy_uuid)

        self.provision_cloud_trust_anchor(cloud_proxy_uuid, cloud_configurations["cloud_id"], cloud_configurations["cloud_trust_anchor"])

        self.provision_cloud_config_info(cloud_proxy_uuid, cloud_configurations["cloud_access_token"], cloud_configurations["cloud_apn"], cloud_configurations["cloud_cis"], cloud_configurations["cloud_id"])

        for i in range(1, self.get_nr_owned_devices()): 
            chili_uuid = self.get_owned_uuid(i)

            self.provision_ace_chili(chili_uuid, cloud_proxy_uuid)
            time.sleep(5)

            self.retrieve_acl2(chili_uuid)
            time.sleep(5)

            self.post_d2dserverlist(cloud_proxy_uuid, "di=" + chili_uuid)
            time.sleep(10)

            # self.retrieve_d2dserverlist(cloud_proxy_uuid)
            # time.sleep(5)

        proxy_time = time.time() - very_start_time
        print (f"Total time taken to proxy all devices to the cloud: {proxy_time:.3} seconds")

        while True: 
            time.sleep(60)
            self.post_d2dserverlist(cloud_proxy_uuid, "scan=1")

    def test_get(self): 
        self.list_owned_devices()
        device_uuid = input("Please enter uuid: ")
        url = input("Please enter request url: ")

        self.general_get(device_uuid, url)

    def test_post(self): 
        self.list_owned_devices()
        device_uuid = input("Please enter uuid: ")
        url = input("Please enter request url: ")
        query = input("Please enter request query: ")
        payload = input("Please enter request payload: ")

        payload_property_list = payload_value_list = payload_type_list = []
        if payload: 
            payload_json = json.loads(payload)
                
            payload_property_list = list(payload_json.keys())
            payload_value_list = list(payload_json.values())
            payload_type_list = []

            for i in range(len(payload_value_list)): 
                # Determine payload type
                if isinstance(payload_value_list[i], bool): 
                    payload_value_list[i] = "1" if payload_value_list[i] else "0"
                    payload_type_list.append("bool")
                elif isinstance(payload_value_list[i], int): 
                    payload_value_list[i] = str(payload_value_list[i])
                    payload_type_list.append("int")
                elif isinstance(payload_value_list[i], float): 
                    payload_value_list[i] = str(payload_value_list[i])
                    payload_type_list.append("float")
                elif isinstance(payload_value_list[i], str): 
                    payload_type_list.append("str")
                else: 
                    print(f"Unrecognised payload type! ")
                    return

        self.general_post(device_uuid, query, url, payload_property_list, payload_value_list, payload_type_list)


    def test_getpost(self): 
        self.discover_all()
        self.onboard_all_unowned()

        self.list_owned_devices()

        obt_uuid = self.get_obt_uuid()

        for i in range(0, self.get_nr_owned_devices()): 
            device_uuid = self.get_owned_uuid(i)

            self.provision_id_cert_all()

            self.provision_ace_chili(device_uuid, obt_uuid)
            time.sleep(5)

            self.retrieve_acl2(device_uuid)
            time.sleep(5)

        while True: 
            type = input("Please enter type of request (get or post): ")

            if type == "get": 
                self.test_get()
            elif type == "post": 
                self.test_post()
            else: 
                print("Invalid input!")
            
            time.sleep(3)

    def get_doxm(self,uuid):
            device = self.get_device(uuid)
            if device:
                print(device.uuid, device.owned_state)
            #self.lib.discover_doxm.argtypes = [String]
            #self.lib.discover_doxm.restype = None
            self.lib.discover_doxm()

        

    def client_command(self,uuid,device_type,command,resource,value):
        if len(uuid) and len(resource):
            print(colored(20*" "+"Client Command->Target:{}-->Type:{}-->Res:{}-->Cmd:{}-->Val:{}"+20*" ",'yellow',attrs=['underline']).format(uuid,device_type,resource,command,value))
            #self.lib.py_post.argtypes = [String]
            #self.lib.py_post.restype = None
            #self.lib.py_post(uuid,command)
            self.lib.discover_resource.argtypes = [String,String]
            self.lib.discover_resource.restype = None
            self.lib.discover_resource(resource,uuid)
            time.sleep(1)
            self.lib.change_light.argtypes = [c_int]
            self.lib.change_light.restype = None
            self.lib.change_light(value)
            return "ok"
        else:
            return "error"



    def test_discovery(self):
        self.discover_all()
        print ("sleeping after discovery issued..")
        time.sleep(3)
        self.onboard_all_unowned()
        time.sleep(3)
        my_uuid = self.get_owned_uuid(0)
        #self.discover_resources(my_uuid)
        self.get_idd(my_uuid)

        time.sleep(3)
        self.offboard_all_owned()


if __name__ == "__main__": 
    my_iotivity = Iotivity()
    signal.signal(signal.SIGINT, my_iotivity.sig_handler)

    # need this sleep, because it takes a while to start Iotivity in C in a Thread
    time.sleep(1)

    # my_iotivity.test_cascoda()

    my_iotivity.test_getpost()

    #my_iotivity.test_discovery()

    #my_iotivity.quit()    









