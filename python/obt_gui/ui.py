#!/usr/bin/env python
#############################
#
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

from ctypes import sizeof
import time
import queue
import signal
import logging
import os
import sys

import json
from json.decoder import JSONDecodeError

import tkinter as tk
from tkinter.constants import END
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, VERTICAL, HORIZONTAL, N, S, E, W

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import iotivity

logger = logging.getLogger(__name__)

app = None

my_iotivity = iotivity.Iotivity()

def show_window_with_text(window_name, my_text):
    """ call back for the IDD file request
    Args:
        client (class): mqtt client
        userdata (not used): not used
        message (class): received mqtt message
        udn (string): udn, the responder udn
    """
    window = tk.Toplevel()
    window.title(window_name)
    text_area = ScrolledText(window, wrap=tk.WORD, width=80, height=50)
    text_area.grid(column=0, pady=10, padx=10)
    text_area.insert(tk.INSERT, my_text)
    text_area.configure(state='disabled')


class QueueHandler(logging.Handler):
    """Class to send logging records to a queue
    It can be used from different threads
    The ConsoleUi class polls this queue to display records in a ScrolledText widget
    """
    # Example from Moshe Kaplan: https://gist.github.com/moshekaplan/c425f861de7bbf28ef06
    # (https://stackoverflow.com/questions/13318742/python-logging-to-tkinter-text-widget) is not thread safe!
    # See https://stackoverflow.com/questions/43909849/tkinter-python-crashes-on-new-thread-trying-to-log-on-main-thread

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class ConsoleUi:
    """Poll messages from a logging queue and display them in a scrolled text widget"""

    def __init__(self, frame):
        self.frame = frame
        # Create a ScrolledText wdiget
        self.scrolled_text = ScrolledText(frame, state='disabled', height=40)
        self.scrolled_text.grid(row=0, column=0, sticky=(N, S, W, E))
        self.scrolled_text.configure(font='TkFixedFont')
        self.scrolled_text.tag_config('INFO', foreground='black')
        self.scrolled_text.tag_config('DEBUG', foreground='gray')
        self.scrolled_text.tag_config('WARNING', foreground='orange')
        self.scrolled_text.tag_config('ERROR', foreground='red')
        self.scrolled_text.tag_config('CRITICAL', foreground='red', underline=1)
        # Create a logging handler using a queue
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter('%(asctime)s: %(message)s')
        self.queue_handler.setFormatter(formatter)
        logger.addHandler(self.queue_handler)
        # Start polling messages from the queue
        self.frame.after(100, self.poll_log_queue)

    def display(self, record):
        msg = self.queue_handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)

    def poll_log_queue(self):
        # Check every 100ms if there is a new message in the queue to display
        while True:
            try:
                record = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record)
        self.frame.after(100, self.poll_log_queue)


class FormUi:

    def __init__(self, frame):
        self.frame = frame

        # Create a combobbox to select the request type
        values = ['GET', 'POST']
        self.request_type = tk.StringVar()
        ttk.Label(self.frame, text='Request Type:').grid(
            column=0, row=0, sticky=W)
        self.combobox = ttk.Combobox(
            self.frame,
            textvariable=self.request_type,
            width=25,
            state='readonly',
            values=values
        )
        self.combobox.current(0)
        self.combobox.grid(column=1, row=0, sticky=W)

        my_width = 60

        # Create a text field to enter the request URL
        self.URL = tk.StringVar()
        ttk.Label(self.frame, text='Request URL:').grid(column=0, row=2, sticky=W)
        ttk.Entry(self.frame, textvariable=self.URL, width=my_width).grid(
            column=1, row=2, sticky=(W, E))
        self.URL.set('oic/d')

        # Create a text field to enter POST query
        self.query = tk.StringVar()
        ttk.Label(self.frame, text='Request Query:').grid(column=0, row=3, sticky=W)
        ttk.Entry(self.frame, textvariable=self.query, width=my_width).grid(
            column=1, row=3, sticky=(W, E))
        self.query.set('')

        # Create a text field to enter Payload as json
        self.payload_json = tk.StringVar()
        ttk.Label(self.frame, text='Request Payload:').grid(column=0, row=6, sticky=W)
        ttk.Entry(self.frame, textvariable=self.payload_json, width=my_width).grid(
            column=1, row=6, sticky=(W, E))
        self.payload_json.set('{"property1": new_value1, "property2": new_value2}')

        row_index = 10
        row_index += 1

        # Add a button to publish the message as cbor
        tk.Label(self.frame, text=' ').grid(column=0, row=row_index, sticky=W)
        self.button = ttk.Button(
            self.frame, text='Send Request', command=self.send_request)
        self.button.grid(column=1, row=row_index, sticky=W)

        row_index += 1
        ttk.Label(self.frame, text='   ').grid(column=0, row=row_index, sticky=W)

        row_index += 1
        # Add a button to do discovery
        tk.Label(self.frame, text='Device Discovery:').grid(column=0, row=row_index, sticky=W)
        self.button = ttk.Button(
            self.frame, text='Discover', command=self.discover_devices)
        self.button.grid(column=1, row=row_index, sticky=W)

        row_index += 1
        # list box section
        tk.Label(self.frame, text='Discovered:').grid(column=0, row=row_index, sticky=W)
        # len_max = len(random_string())
        self.l1 = tk.Listbox(self.frame, height=3, width=my_width, exportselection=False)
        self.l1.grid(column=1, row=row_index, sticky=(W, E))

        row_index += 3
        # Add a button to publish the message as cbor
        self.button_clear = ttk.Button(self.frame, text='Clear', command=self.submit_clear)
        self.button_clear.grid(column=0, row=row_index, sticky=W)

    def update_display(self): 
        time.sleep(0.1)
        app.root.update()

    def discover_devices(self): 
        logger.log(logging.INFO, f"Doing device discovery")
        self.update_display()
        my_iotivity.discover_all()

        nr_unowned = my_iotivity.get_nr_unowned_devices()
        logger.log(logging.INFO, f"{nr_unowned} devices discovered: ")
        self.update_display()

        for i in range(nr_unowned):
            unowned_uuid = my_iotivity.get_unowned_uuid(i)
            unowned_name = my_iotivity.get_device_name(unowned_uuid)
            logger.log(logging.INFO, f"Unowned No.{i}: {unowned_uuid} - {unowned_name}")
            self.update_display()

        logger.log(logging.INFO, f"Onboarding all devices")
        self.update_display()
        my_iotivity.onboard_all_unowned()
        my_iotivity.list_owned_devices()
        nr_owned = my_iotivity.get_nr_owned_devices()
        logger.log(logging.INFO, f"{nr_owned}/{nr_unowned} devices onboarded")
        self.update_display()

        obt_uuid = my_iotivity.get_obt_uuid()

        for i in range(0, my_iotivity.get_nr_owned_devices()): 
            device_uuid = my_iotivity.get_owned_uuid(i)
            device_name = my_iotivity.get_device_name(device_uuid)
            device_info = f"{device_uuid} - {device_name}"
            logger.log(logging.INFO, f"Provisioning device No.{i}: {device_info}")
            self.update_display()

            discovered_devices = app.form.l1.get(0, END)
            if device_info not in discovered_devices:
                app.form.l1.insert(END, device_info)

                my_iotivity.provision_id_cert(device_uuid)

                my_iotivity.provision_ace_chili(device_uuid, obt_uuid)

    def send_request(self): 
        if self.l1.curselection() == (): 
            print("No device selected!")
            return

        device_index = int(self.l1.curselection()[0])
        device_uuid = my_iotivity.get_owned_uuid(device_index)

        if self.request_type.get() == 'GET': 
            request_url = self.URL.get()

            result, response_payload = my_iotivity.general_get(device_uuid, request_url)

            if result: 
                logger.log(logging.INFO, f"GET {request_url} succeeded")
                self.update_display()
                show_window_with_text(f"{self.request_type.get()} {request_url} response payload", response_payload)
            else: 
                logger.log(logging.INFO, f"GET {request_url} failed")
                self.update_display()
        elif self.request_type.get() == 'POST': 
            request_query = self.query.get()
            request_url = self.URL.get()

            payload_json_str = self.payload_json.get()
            payload_property_list = payload_value_list = payload_type_list = []
            
            if payload_json_str: 
                json_data = json.loads(payload_json_str)
                
                payload_property_list = list(json_data.keys())
                payload_value_list = list(json_data.values())
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
                        logger.log(logging.INFO, f"Unrecognised payload type! ")
                        self.update_display()
                        return

            result, response_payload = my_iotivity.general_post(device_uuid, request_query, request_url, payload_property_list, payload_value_list, payload_type_list)

            if result: 
                logger.log(logging.INFO, f"POST {request_url} succeeded")
                self.update_display()
                show_window_with_text(f"POST {request_url} response payload", response_payload)
            else: 
                logger.log(logging.INFO, f"POST {request_url} failed")
                self.update_display()

    def submit_clear(self):
        """ clear the discovered device list
        """
        print("Clear - delete all devices")
        logger.log(logging.INFO, "Clear - offboard all devices")
        self.update_display()
        self.l1.delete(0, END)
        my_iotivity.offboard_all_owned()

class App:

    def __init__(self, root):
        """ create the application, having 3 panes.
        """
        self.root = root
        root.title('OBT GUI')

        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Config", command=donothing)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About...", command=donothing)

        root.config(menu=menubar)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Create the panes and frames
        vertical_pane = ttk.PanedWindow(self.root, orient=VERTICAL)
        vertical_pane.grid(row=0, column=0, sticky="nsew")
        # vertical_pane.grid(row=1, column=1, sticky="nsew")
        horizontal_pane = ttk.PanedWindow(vertical_pane, orient=HORIZONTAL)

        vertical_pane.add(horizontal_pane)
        form_frame = ttk.Labelframe(
            horizontal_pane, text="Publish Information")
        form_frame.columnconfigure(1, weight=1)
        horizontal_pane.add(form_frame, weight=1)

        console_frame = ttk.Labelframe(horizontal_pane, text="Console")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        horizontal_pane.add(console_frame, weight=1)

        # Initialize all frames
        self.form = FormUi(form_frame)
        self.form.app = self
        self.console = ConsoleUi(console_frame)
        self.console.app = self
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        """ quit function for the app
        """
        my_iotivity.offboard_all_owned()
        self.root.destroy()

def donothing():
    filewin = tk.Toplevel(app.root)
    button = tk.Button(filewin, text="Do nothing button")
    button.pack()

def main():
    # initalize the GUI application
    global app
    root = tk.Tk()
    app = App(root)

    logging.basicConfig(level=logging.DEBUG)
    logger.log(logging.INFO, "Onboarding tool started with UUID: " + my_iotivity.get_obt_uuid())

    # app.root.config(menu=menubar)
    app.root.mainloop()

    my_iotivity.quit() 

if __name__ == '__main__':
    main()
