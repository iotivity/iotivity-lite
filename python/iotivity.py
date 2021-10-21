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

import numpy.ctypeslib as ctl

import uuid

import threading
import time

import json

import requests


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


CHANGED_CALLBACK = CFUNCTYPE(None)
RESOURCE_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p, c_char_p, c_char_p)

class Iotivity():
    # needs to be before _init_
    def changedCB(self):
        print("=====  lists changed ========")
        self.list_unowned_devices()
        self.list_owned_devices()
        print("=====  lists changed: done ========")
    
    def resourceCB(self, anchor, uri, rtypes, myjson):
        uuid = str(anchor)[8:-1]
        my_uri = str(uri)[2:-1]

        print("=  Resource callback ", uuid, my_uri)
        my_str = str(myjson)[2:-1]

        if self.resourcelist.get(uuid) is None:
            mylist = [ my_str ]
            self.resourcelist[uuid] = mylist
        else:
            mylist = self.resourcelist[uuid]
            mylist.append(my_str)
            self.resourcelist[uuid] = mylist
        #print (" -----resourcelist ", self.resourcelist)


    def __init__(self):
        print ("loading ...")
        libname = 'libiotivity-lite-client-python.so'
        libdir = './'
        self.lib=ctl.load_library(libname, libdir)
        # python list of copied unowned devices on the local network
        # will be updated from the C layer automatically by the CHANGED_CALLBACK
        self.unowned_devices = []
        # python list of copied owned devices on the local network
        # will be updated from the C layer automatically by the CHANGED_CALLBACK
        self.owned_devices = []
        # resource list
        self.resourcelist = {}

        print (self.lib)
        print ("...")
        self.lib.oc_set_con_res_announced(c_bool(False));
        print("oc_set_con_res_announced - done")
        self.lib.oc_set_max_app_data_size(c_size_t(16384));
        print("oc_set_max_app_data_size- done")
        value = self.lib.oc_get_max_app_data_size()
        print("oc_get_max_app_data_size :", value)
        self.changedCB = CHANGED_CALLBACK(self.changedCB)
        self.lib.install_changedCB(self.changedCB)

        self.resourceCB = RESOURCE_CALLBACK(self.resourceCB)
        self.lib.install_resourceCB(self.resourceCB)

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
        self.lib.display_device_uuid();
        
    def discover_unowned(self):
        print("discover_unowned ")
        # OBT application
        ret = self.lib.discover_unowned_devices(c_int(0x02))
        #ret = self.lib.discover_unowned_devices(c_int(0x03))
        #ret = self.lib.discover_unowned_devices(c_int(0x05))
        time.sleep(3)
        # python callback application
        #ret = self.lib.oc_obt_discover_unowned_devices(unowned_device_cb, None)
        #ret = self.lib.py_discover_unowned_devices()
        print("discover_unowned- done")

    def discover_all(self):
        self.discover_unowned()
        self.discover_owned()
        time.sleep(3)
        self.list_owned_devices()
        self.list_unowned_devices()

        
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
        print("discover_owned ")
        ret = self.lib.discover_owned_devices(c_int(0x02))
        #ret = self.lib.discover_owned_devices(c_int(0x03))
        #ret = self.lib.discover_owned_devices(c_int(0x05))
        # call with call back in python
        #ret = self.lib.oc_obt_discover_owned_devices(owned_device_cb, None)
        print("discover_owned- done")

        
    def quit(self):
        self.lib.python_exit(c_int(0))

    def sig_handler(self, signum, frame):
        print ("sig_handler..")
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
        return device_name

    def get_device_name(self, device_uuid):
        # retrieves the uuid of the owned device
        # index of owned list of devices in IoTivity layer
        self.lib.get_device_name_from_uuid.argtypes = [String]
        if sizeof(c_int) == sizeof(c_void_p):
            self.lib.get_device_name_from_uuid.restype = ReturnString
        else:
            self.lib.get_device_name_from_uuid.restype = String
            self.lib.get_device_name_from_uuid.errcheck = ReturnString
        return self.lib.get_device_name_from_uuid(device_uuid)


    def onboard_all_unowned(self):
        print ("onboard_all_unowned: listing NOT onboarded devices in C:")
        self.list_unowned_devices()


        print ("onboarding...")
        self.lib.py_otm_just_works.argtypes = [String]
        self.lib.py_otm_just_works.restype = None
        for device in self.unowned_devices:
            print ("onboard device :", device, self.get_device_name(device))
            self.lib.py_otm_just_works(device)
            time.sleep(3)

        print ("...done.")

    
    def offboard_all_owned(self):
        print ("listing onboarded devices:")
        self.list_owned_devices()

        print ("offboarding...")
        self.lib.py_reset_device.argtypes = [String]
        self.lib.py_reset_device.restype = None
        for device in self.owned_devices:
            print ("offboard device :", device)
            self.lib.py_reset_device(device)
        print ("...done.")


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
    
    def provision_id_cert(self, device_uuid):
        self.lib.py_provision_id_cert.argtypes = [String]
        self.lib.py_provision_id_cert.restype = None
        print( "py_provision_id_cert:",device_uuid)
        self.lib.py_provision_id_cert(device_uuid)

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
        self.lib.py_discover_resources(myuuid)

    def retrieve_acl2(self, myuuid): 
        self.lib.py_retrieve_acl2.argtypes = [String]
        self.lib.py_retrieve_acl2.restype = None
        self.lib.py_retrieve_acl2(myuuid)

    def provision_cloud_trust_anchor(self, myuuid, cloud_id, cloud_trust_anchor): 
        self.lib.py_provision_cloud_trust_anchor.argtypes = [String, String, String]
        self.lib.py_provision_cloud_trust_anchor.restype = None
        self.lib.py_provision_cloud_trust_anchor(myuuid, cloud_id, cloud_trust_anchor)

    def provision_cloud_config_info(self, myuuid, cloud_access_token, cloud_apn, cloud_cis, cloud_id): 
        self.lib.py_provision_cloud_config_info.argtypes = [String, String, String, String, String]
        self.lib.py_provision_cloud_config_info.restype = None
        self.lib.py_provision_cloud_config_info(myuuid, cloud_access_token, cloud_apn, cloud_cis, cloud_id)

    def get_idd(self, myuuid):
        print("get_idd ", myuuid)
        self.discover_resources(myuuid)
        time.sleep(3)
        
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


    def test_security(self):
        url = 'https://192.168.202.112:8443/.well-known/cloud-configuration'
        r = requests.get(url, verify=False)

        content = r.json()
        cloud_id = content['cloudId']
        cloud_trust_anchor = content['cloudCertificateAuthorities']
        cloud_apn = content['cloudAuthorizationProvider']
        cloud_cis = content['cloudUrl']
        cloud_access_token = "test"

        self.discover_all()

        print ("sleeping after discovery issued..")
        time.sleep(3)
        self.onboard_all_unowned()

        time.sleep(3)
        my_iotivity.provision_ace_all()

        time.sleep(3)
        my_iotivity.provision_id_cert_all()

        time.sleep(3)
        my_uuid = self.get_owned_uuid(0)
        # self.provision_role_cert(my_uuid, "my_role", "my_auth")
        # self.provision_role_cert(my_uuid, "my_2nd_role", None)

        time.sleep(3)
        self.discover_resources(my_uuid)

        time.sleep(3)
        self.retrieve_acl2(my_uuid)

        time.sleep(3)
        my_iotivity.provision_cloud_trust_anchor(my_uuid, cloud_id, cloud_trust_anchor)

        time.sleep(3)
        my_iotivity.provision_cloud_config_info(my_uuid, cloud_access_token, cloud_apn, cloud_cis, cloud_id)

        time.sleep(3)
        self.offboard_all_owned()


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



my_iotivity = Iotivity()
signal.signal(signal.SIGINT, my_iotivity.sig_handler)

# need this sleep, because it takes a while to start Iotivity in C in a Thread
time.sleep(1)

my_iotivity.test_security()

#my_iotivity.test_discovery()

my_iotivity.quit()    









