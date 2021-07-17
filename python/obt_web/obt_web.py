#from app import app
#from flask_socketio import SocketIO

#socketio = SocketIO(app)
#socketio.run(app,host='0.0.0.0')

#add parent directory to path so we can import iotivity
import os, sys, time
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from threading import Lock
import signal
import simplejson as json

from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO
from iotivity import Iotivity

thread = None
thread_lock = Lock()


def to_json(obj):
    return json.dumps(obj, default=lambda obj: obj.__dict__)

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
socketio = SocketIO(app, async_mode='threading')

@app.route('/')
def sessions(methods=['GET','POST']):
    return render_template('index.html')



@app.route('/include/<path:path>')
def send_js(path):
    print("path:{}".format(path))
    return send_from_directory('include', path)

@socketio.on('discover_devices')
def handle_event(data):
    print("Discover Unowned Devices X"+data);
    unowned_devices_bytelist = my_iotivity.discover_unowned()
    print("OBT: {}".format(unowned_devices_bytelist))
    #socketio.emit('unowned',json.dumps(unowned_devices_bytelist))
    print("Discover Owned Devices X"+data);
    owned_devices_bytelist = my_iotivity.discover_owned()
    print("OBT: {}".format(owned_devices_bytelist))
    #socketio.emit('owned',json.dumps(owned_devices_bytelist))
    devices_array = my_iotivity.return_devices_array()
    socketio.emit('device_discovery',to_json(devices_array))
    print(to_json(devices_array))

@socketio.on('discover_unowned')
def handle_event(data):
    print("Discover Unowned Devices X"+data);
    unowned_devices_bytelist = my_iotivity.discover_unowned()
    print("OBT: {}".format(unowned_devices_bytelist))
    socketio.emit('unowned',json.dumps(unowned_devices_bytelist))

@socketio.on('discover_owned')
def handle_event(data):
    print("Discover Owned Devices X"+data);
    owned_devices_bytelist = my_iotivity.discover_owned()
    print("OBT: {}".format(owned_devices_bytelist))
    socketio.emit('owned',json.dumps(owned_devices_bytelist))

@socketio.on('discover_resources')
def handle_event(data):
    print("Discover Resources Device :{}".format(data));
    owned_devices_resourcelist = my_iotivity.discover_resources(data)
    print("OBT Resources: {}".format(owned_devices_resourcelist))
    #socketio.emit('owned',json.dumps(owned_devices_bytelist))

@socketio.on('onboard_device')
def handle_onboard(data):
    print("Onboard Device:{}".format(data))
    onboard_device = my_iotivity.onboard_device(data)
    print("OBT: {}".format(onboard_device))

@socketio.on('offboard_device')
def handle_offonboard(data):
    print("Offboard Device:{}".format(data))
    onboard_device = my_iotivity.offboard_device(data)
    print("OBT: {}".format(onboard_device))

#@socketio.event
#def connect():
#    global thread
#    with thread_lock:
#        if thread is None:
#            thread = socketio.start_background_task(background_thread)
#    socketio.emit('my_response', {'data': 'Connected', 'count': 0})

if __name__ == '__main__':
    my_iotivity = Iotivity()
    signal.signal(signal.SIGINT, my_iotivity.sig_handler)
    socketio.emit('obt_initialized','True')
    time.sleep(5)
    #Insecure
    #socketio.run(app, host='0.0.0.0',debug=True,use_reloader=False)
    #Secure Self-signed (required for camera)
    socketio.run(app, host='0.0.0.0',debug=True,use_reloader=False,ssl_context=('cert.pem', 'key.pem'))




