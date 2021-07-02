#from app import app
#from flask_socketio import SocketIO

#socketio = SocketIO(app)
#socketio.run(app,host='0.0.0.0')

#add parent directory to path so we can import iotivity
import os, sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

import signal

from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO
from iotivity import Iotivity



my_iotivity = Iotivity()

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
socketio = SocketIO(app)

@app.route('/')
def sessions(methods=['GET','POST']):
    return render_template('index.html')



@app.route('/include/<path:path>')
def send_js(path):
    print("path:{}".format(path))
    return send_from_directory('include', path)

@socketio.on('message')
def handle_message(data):
    print("Discover Unowned Devices"+data);
    my_iotivity.discover_unowned();
    socketio.send('unowned_devices')



if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0',debug=True)
    signal.signal(signal.SIGINT, my_iotivity.sig_handler)

    socketio.emit('obt_initialized','True')
