import os
import wpa_ctrl_iface as wpa_ctrl

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





