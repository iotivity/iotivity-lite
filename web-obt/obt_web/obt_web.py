#from app import app
#from flask_socketio import SocketIO

#socketio = SocketIO(app)
#socketio.run(app,host='0.0.0.0')

#add parent directory to path so we can import iotivity
import os, sys, time
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import signal
import simplejson as json
import threading
from types import SimpleNamespace

from flask import Flask, render_template, send_from_directory,request
from flask_socketio import SocketIO
from iotivity import Iotivity

#hostapd integration
import WPACtrl


#change this for DPP
SSID= "IOT"
PASSWORD = "secureyouriot"

ssid = SSID.encode("utf-8").hex()
password = PASSWORD.encode("utf-8").hex()



def to_json(obj):
    return json.dumps(obj, default=lambda obj: obj.__dict__)

app = Flask(__name__)

#Load app secret from file
app.config.from_pyfile('secret')
socketio = SocketIO(app, async_mode='threading')

@app.route('/')
def sessions(methods=['GET','POST']):
    return render_template('index.html')

#DPP listener
@app.route('/dpp',methods=['POST'])
def handle_dpp():
    dpp = request.data.decode('utf-8')
    print(dpp)
    ret = wpa.request('DPP_CONFIGURATOR_ADD')
    print(ret)
    dpp_ret = wpa.request("DPP_QR_CODE " + dpp)
    print(dpp_ret)
    dpp_auth_ret = wpa.request("DPP_AUTH_INIT peer=1 conf=sta-psk configurator=1 ssid="+ssid+" pass="+password)
    print(dpp_auth_ret)
    return ('',200)

@app.route('/include/<path:path>')
def send_js(path):
    print("path:{}".format(path))
    return send_from_directory('include', path)

"""
Listen for incoming connections from website
Discover unowned, owned then resources
"""
@socketio.on('discover_devices')
def handle_event(data):
    #print("Discover Unowned Devices"+data);
    unowned_devices_array = my_iotivity.discover_unowned()
    socketio.emit('device_discovery',to_json(unowned_devices_array))
    for device in unowned_devices_array:
        resources_array = my_iotivity.discover_resources(device.uuid)
        #my_iotivity.get_doxm(device.uuid)
        socketio.emit('resource_discovery',to_json(resources_array))
    #print("Discover Owned Devices X"+data);
    owned_devices_array = my_iotivity.discover_owned()
    socketio.emit('device_discovery',to_json(owned_devices_array))
    for device in owned_devices_array:
        resources_array = my_iotivity.discover_resources(device.uuid)
        #my_iotivity.get_doxm(device.uuid)
        socketio.emit('resource_discovery',to_json(resources_array))


@socketio.on('onboard_device')
def handle_onboard(data):
    print("Onboard Device:{}".format(data))
    device = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
    onboard_device = my_iotivity.onboard_device(device)

@socketio.on('request_random_pin')
def handle_random_pin_request(data):
    print("Random PIN:{}".format(data))
    device = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
    random_pin_ret = my_iotivity.request_random_pin(device)
    socketio.emit('random_pin_request_return',to_json(random_pin_ret))

@socketio.on('offboard_device')
def handle_offonboard(data):
    print("Offboard Device:{}".format(data))
    onboard_device = my_iotivity.offboard_device(data)

@socketio.on('provision_credentials')
def handle_pairwise(data):
    print("Provision Pairwise Device:{}".format(data))
    credentials = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
    for target in credentials.target_devices:
        print("Provision Pairwise Source Device:{} Target Device:{}".format(credentials.source_device,target))
        provision = my_iotivity.provision_pairwise(target,credentials.source_device)

@socketio.on('provision_ace')
def handle_pairwise(data):
    print("Provision ACE:{}".format(data))
    ace = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
    crudn = "|".join(ace.crudn)
    if ace.href is None:
        href = ""
    else:
        href = ace.href
    print(href)
    for subject in ace.subjects:
        provision = my_iotivity.provision_ace(ace.target_device,str(subject),str(href),crudn)

@socketio.on('discover_diplomats')
def discover_diplomats(data):
    diplomat = my_iotivity.discover_diplomats()
    print("Diplomat:{}".format(to_json(diplomat)))
    socketio.emit('discover_diplomats',to_json(diplomat))

@socketio.on('set_diplomat_observe')
def diplomat_set_observe(state):
    diplomat = my_iotivity.diplomat_set_observe(state)
    socketio.emit('diplomat_state',to_json(diplomat))

@socketio.on('send_command')
def send_command(uuid,device_type,command,resource,value):
    #print("Device:{},Device Type:{},Command:{},Resource:{},Value:{}".format(uuid,device_type,command,resource,value))
    ret = my_iotivity.client_command(uuid,device_type,command,resource,value)

@socketio.on('get_obt_uuid')
def get_obt_uuid():
    uuid = my_iotivity.get_obt_uuid()
    print(uuid)
    socketio.emit('obt_uuid',to_json({"uuid":uuid}))

@socketio.on('disocnnect')
def send_disconnect():
    print("diconnected")

#@socketio.event
#def connect():
#    global thread
#    with thread_lock:
#        if thread is None:
#            thread = socketio.start_background_task(background_thread)
#    socketio.emit('my_response', {'data': 'Connected', 'count': 0})

if __name__ == '__main__':

    #initiate hostapd socket
    wpa = WPACtrl.WPACtrl("/var/run/hostapd/wlan1")
    #attach event listener
    wpa.attach()


    #debug = ['resources']
    debug = []
    my_iotivity = Iotivity(debug=debug)
    signal.signal(signal.SIGINT, my_iotivity.sig_handler)
    #Insecure
    #socketio.run(app, host='0.0.0.0',debug=True,use_reloader=False)
    #run in seperate thread
    #threading.Thread(target=app.run(host='0.0.0.0',ssl_context=('cert.pem','key.pem'))).start()
    #Secure Self-signed (required for camera) See README for cert
    socketio.run(app, host='0.0.0.0',debug=False,use_reloader=True,ssl_context=('cert.pem', 'key.pem'))




