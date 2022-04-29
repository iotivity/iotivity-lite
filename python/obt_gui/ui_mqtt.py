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
from tkinter.filedialog import askopenfilename
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

class ToolTip(object):

    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 30
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                      background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                      font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

def CreateToolTip(widget, text):
    toolTip = ToolTip(widget)
    def enter(event):
        toolTip.showtip(text)
    def leave(event):
        toolTip.hidetip()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

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

        my_width = 60
        
        row_index = 1
        # Create a text field to enter MQTT Server
        self.mqtt_server = tk.StringVar()
        ttk.Label(self.frame, text='MQTT Server:').grid(column=0, row=row_index, sticky=W)
        ttk.Entry(self.frame, textvariable=self.mqtt_server, width=my_width).grid(
            column=1, row=row_index, sticky=(W, E))
        self.mqtt_server.set('localhost')

        row_index += 1
        # Create a text field to enter MQTT Port
        self.mqtt_port = tk.StringVar()
        ttk.Label(self.frame, text='MQTT Port:').grid(column=0, row=row_index, sticky=W)
        ttk.Entry(self.frame, textvariable=self.mqtt_port, width=my_width).grid(
            column=1, row=row_index, sticky=(W, E))
        self.mqtt_port.set('1883')

        row_index += 1
        # Create a text field to enter target device names
        self.names = tk.StringVar()
        ttk.Label(self.frame, text='Device Name Contains:').grid(column=0, row=row_index, sticky=W)
        self.entry_names = ttk.Entry(self.frame, textvariable=self.names, width=my_width)
        self.entry_names.grid(column=1, row=row_index, sticky=(W, E))
        CreateToolTip(self.entry_names, 'Substrings of device names to be proxied (not case sensitive)\ne.g. Enter "sensor" to proxy all devices that has "sensor" in their name.\nMultiple arguments allowed (separate by ",")\ne.g. sensor,actuator\nDefault: Proxy all discovered devices')

        row_index += 1
        # Add a button to start proxy
        tk.Label(self.frame, text='Start/Restart Proxy:').grid(column=0, row=row_index, sticky=W)
        self.button_proxy = ttk.Button(
            self.frame, text='Proxy', command=self.start_proxy)
        self.button_proxy.grid(column=1, row=row_index, sticky=W)

        row_index += 1
        ttk.Label(self.frame).grid(column=0, row=row_index, sticky=W)

        row_index += 2
        # List proxied devices
        tk.Label(self.frame, text='Proxied devices:').grid(column=0, row=row_index, sticky=W)
        self.l1 = tk.Listbox(self.frame, height=3, width=my_width, exportselection=False)
        self.l1.grid(column=1, row=row_index, sticky=(W, E))

        row_index += 1
        ttk.Label(self.frame, text='   ').grid(column=0, row=row_index, sticky=W)

        row_index += 1
        # Add buttons for further actions
        self.button_reset = ttk.Button(self.frame, text='Reset All Devices', command=self.reset_all)
        self.button_reset.grid(column=0, row=row_index, sticky=W)
        CreateToolTip(self.button_reset, 'Reset all devices and stop proxy')

    def update_display(self): 
        time.sleep(0.1)
        app.root.update()

    def start_proxy(self): 
        """ Start MQTT Proxy
        """
        logger.log(logging.INFO, f"Starting MQTT proxy...")
        self.update_display()

        target_names = self.names.get()
        target_names_list = target_names.split(",")
        for i, target_name in enumerate(target_names_list): 
            target_names_list[i] = target_name.strip()

        target_mqtt_server = self.mqtt_server.get()
        target_mqtt_port = self.mqtt_port.get()
        my_iotivity.proxy_to_mqtt(target_names_list, target_mqtt_server, target_mqtt_port)

        for i in range(0, my_iotivity.get_nr_owned_devices()): 
            device_uuid = my_iotivity.get_owned_uuid(i)
            device_name = my_iotivity.get_device_name(device_uuid)
            device_info = f"{device_uuid} - {device_name}"
            logger.log(logging.INFO, f"Proxied device No.{i}: {device_info}")
            self.update_display()

            discovered_devices = self.l1.get(0, END)
            if device_info not in discovered_devices:
                self.l1.insert(END, device_info)        

    def reset_all(self):
        """ Reset all devices and stop proxy
        """
        print("Resetting all devices")
        logger.log(logging.INFO, "Resetting all devices")
        self.update_display()
        self.l1.delete(0, END)
        my_iotivity.general_delete(my_iotivity.get_owned_uuid(0), "delete=all", "d2dserverlist")
        my_iotivity.offboard_all_owned()

class App:

    def __init__(self, root):
        """ create the application, having 3 panes.
        """
        self.root = root
        root.title('OCF MQTT Proxy GUI')

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
            horizontal_pane, text="Configurations")
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
        my_iotivity.general_delete(my_iotivity.get_owned_uuid(0), "delete=all", "d2dserverlist")
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