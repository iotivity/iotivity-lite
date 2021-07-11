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


@socketio.on('discover_unowned')
def handle_event(data):
    print("Discover Unowned Devices X"+data);
    unowned_devices_bytelist = my_iotivity.discover_unowned()
    print("OBT: {}".format(unowned_devices_bytelist))
    #my_dict = {"0": "ff032204-f580-4f92-6eef-bee073446044", "1": "a796eed7-3704-4428-75a3-497a2d584ee9"}
    #socketio.emit('unowned',json.dumps(my_dict))
    socketio.emit('unowned',json.dumps(unowned_devices_bytelist))


@socketio.on('onboard_device')
def handle_onboard(data):
    print("Onboard Device:{}".format(data))
    onboard_device = my_iotivity.onboard_device(data)


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
    socketio.run(app, host='0.0.0.0',debug=True,use_reloader=False)




