from app import app
from flask import Flask, render_template

@app.route('/')
@app.route('/index')
def index():
    return render_template("session.html")

@socketio.on('event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)
