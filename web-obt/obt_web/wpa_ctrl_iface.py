import os

try:
    from gevent import (socket, select)
except ImportError:
    import socket, select

''' # Incompatibilities

Generally, socker errors are handled in a more pythonic manor.
While the original wpa_ctrl.c implementation deals with a lot of error
handling and returns different error codes (as it surely should, since it's
a C library), this implementation simply does not handle socket exceptions.

## wpa_ctrl_request()
* Does not use cmd_len, since there's really no need for this in the python implementation.
* Does not take a reply buffer pointer, since we'll just receive into a new string.
  It does however use reply_len as size hinting for recv.
* The msg_cb only takes a msg argument, not len.

## wpa_ctrl_recv()
* Does not take a reply buffer pointer, for the same reason mentioned for wpa_ctrl_request()
'''

class wpa_ctrl(object):
    s = local = dest = None

def wpa_ctrl_open(ctrl_path):
    '''
    Open a control interface to wpa_supplicant/hostapd.
    '''

    ctrl = wpa_ctrl()

    try:
        ctrl.s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    except socket.error:
        print(socket.error)
        return None

    ctrl.local = '/tmp/wpa_ctrl_%d-%d' % (os.getpid(), wpa_ctrl_open.counter)
    wpa_ctrl_open.counter += 1

    try:
        ctrl.s.bind(ctrl.local)
    except socket.error:
        ctrl.s.close()

        return None

    try:
        ctrl.s.connect(ctrl_path)
    except socket.error:
        wpa_ctrl_close(ctrl)

        return None

    return ctrl

wpa_ctrl_open.counter = 0

def wpa_ctrl_close(ctrl):
    '''
    Close a control interface to wpa_supplicant/hostapd.
    '''

    os.unlink(ctrl.local)
    ctrl.s.close()

def wpa_ctrl_request(ctrl, cmd, msg_cb=None, reply_len=4096):
    '''
    Send a command to wpa_supplicant/hostapd.
    '''

    ctrl.s.send(cmd.encode())

    while True:
        rlist, wlist, xlist = select.select([ctrl.s], [], [], 2)

        if rlist and (ctrl.s in rlist):
            data = ctrl.s.recv(reply_len)

            if data and data[0] == '<':
                if msg_cb:
                    msg_cb(data)

                continue
            else:
                return data
        else:
            return -2 # Timed out


def wpa_ctrl_attach_helper(ctrl, attach):
    ret = wpa_ctrl_request(ctrl, 'ATTACH' if attach else 'DETACH')
    try:
      basestring
    except NameError:
      basestring = str

    if isinstance(ret, basestring):
        return ret == 'OK\n'
    else:
        return ret

def wpa_ctrl_attach(ctrl):
    '''
    Register as an event monitor for the control interface.
    '''
    return wpa_ctrl_attach_helper(ctrl, True)

def wpa_ctrl_detach(ctrl):
    '''
    Unregister event monitor from the control interface.
    '''
    return wpa_ctrl_attach_helper(ctrl, False)

def wpa_ctrl_recv(ctrl, reply_len=4096):
    '''
    Receive a pending control interface message.
    '''
    return ctrl.s.recv(reply_len)

def wpa_ctrl_pending(ctrl):
    '''
    Check whether there are pending event messages.
    '''

    rlist, wlist, xlist = select.select([ctrl.s], [], [], 0)

    return ctrl.s in rlist

def wpa_ctrl_get_fd(ctrl):
    '''
    Get file descriptor used by the control interface.
    '''

    return ctrl.s.fileno()


class WPACtrl:

    def __init__(self, ctrl_iface_path):
        self.attached = 0

        self.ctrl_iface_path = ctrl_iface_path

        self.ctrl_iface = wpa_ctrl.wpa_ctrl_open(ctrl_iface_path)

        if not self.ctrl_iface:
            raise error('wpa_ctrl_open failed')


    def close(self):
        if self.attached == 1:
            self.detach()

        wpa_ctrl.wpa_ctrl_close(self.ctrl_iface)

    def __del__(self):
        self.close()

    def request(self, cmd):
        '''
        Send a command to wpa_supplicant/hostapd. Returns the command response
		in a string.
        '''

        try:
            data = wpa_ctrl.wpa_ctrl_request(self.ctrl_iface, cmd)
        except wpa_ctrl.socket.error:
            raise error('wpa_ctrl_request failed')

        if data == -2:
            raise error('wpa_ctrl_request timed out')

        return data

    def attach(self):
        '''
        Register as an event monitor for the control interface.
        '''
        if self.attached == 1:
            return

        try:
            ret = wpa_ctrl.wpa_ctrl_attach(self.ctrl_iface)
        except wpa_ctrl.socket.error:
            raise error('wpa_ctrl_attach failed')

        if ret == True:
            self.attached = 1
        elif ret == -2:
            raise error('wpa_ctrl_attach timed out')

    def detach(self):
        '''
        Unregister event monitor from the control interface.
        '''
        if self.attached == 0:
            return

        try:
            ret = wpa_ctrl.wpa_ctrl_detach(self.ctrl_iface)
        except wpa_ctrl.socket.error:
            raise error('wpa_ctrl_detach failed')

        if ret == True:
            self.attached = 0
        elif ret == -2:
            raise error('wpa_ctrl_attach timed out')

    def pending(self):
        '''
        Check if any events/messages are pending. Returns True if messages are pending,
		otherwise False.
        '''
        try:
            return wpa_ctrl.wpa_ctrl_pending(self.ctrl_iface)
        except wpa_ctrl.socket.error:
            raise error('wpa_ctrl_pending failed')

    def recv(self):
        '''
        Recieve a pending event/message from ctrl socket. Returns a message string.
        '''
        data = wpa_ctrl.wpa_ctrl_recv(self.ctrl_iface)
        return data

    def scanresults(self):
        '''
        Return list of scan results. Each element of the scan result list is a string
		of properties for a single BSS. This method is specific to wpa_supplicant.
        '''

        bssids = []

        for cell in range(1000):
            ret = self.request('BSS %d' % cell)
            print(ret)
            if 'bssid=' in ret:
                bssids.append(ret)
            else:
                break

        return bssids

class error(Exception): pass





