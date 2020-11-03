"""
# coding:utf-8
@Time    : 2020/11/03
@Author  : jiangwei
@mail    : jiangwei1@kylinos.cn
@File    : app.py.py
@Software: PyCharm
"""
from flask import Flask, render_template, request, redirect, url_for, abort, session, flash
from flask_session import Session
from flask_socketio import SocketIO, disconnect, rooms
import os
import select
import termios
import pty
import struct
import fcntl
import psutil
from setting import BaseConfig, TERM_INIT_CONFIG

app = Flask(__name__)
app.config.from_object(BaseConfig)
Session(app)

socket_io = SocketIO(app, manage_session=False, logger=False, engineio_logger=False)


def set_win_size(fd, row, col, xpix=0, ypix=0):
    win_size = struct.pack('HHHH', row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, win_size)


def read_and_forward_pty_output(fd=None, pid=None, room_id=None):
    max_read_bytes = 1024 * 20
    while True:
        socket_io.sleep(0.15)
        try:
            child_process = psutil.Process(pid)
        except psutil.NoSuchProcess as err:
            return err
        if child_process.status() not in ('running', 'sleeping'):
            return
        if fd:
            timeout_sec = 0
            (data_ready, _, _) = select.select([fd], [], [], timeout_sec)
            if data_ready:
                try:
                    output = os.read(fd, max_read_bytes).decode()
                except Exception as e:
                    output = """
                    ***AQUI WEB TERM ERR***
                    {}
                    ***********************
                    """.format(e)
                socket_io.emit('pty-output', {'output': output}, namespace='/pty', room=room_id)


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/auth/login/')
def login():
    username = request.args.get('username')
    pwd = request.args.get('password')
    if username == 'jiangwei' and pwd == 'jiangW3521946.':
        return redirect(url_for('.connect', conn_cate='ssh', hostname='ubuntu', port=22))
    else:
        flash('用户名密码错误!')
        return redirect(url_for('.login'))


@app.route('/connect-remote-host/<string:conn_cate>/<string:hostname>/<int:port>/')
def connect(conn_cate, hostname, port):
    if conn_cate not in ['ssh', 'telnet']:
        return abort(404, '暂时只支持ssh以及telnet连接方式!')
    session['terminal_config'] = TERM_INIT_CONFIG
    session['terminal_config']['term_type'] = conn_cate
    session['terminal_config']['username'] = hostname
    session['terminal_config']['port'] = port
    session.modified = True
    return render_template('index.html')


@socket_io.on("pty-input", namespace="/pty")
def pty_input(data):
    """write to the child pty, which now is the ssh process from this machine to the 'domain' configured
    """
    try:
        child_process = psutil.Process(session.get('terminal_config').get('child_pid'))
    except psutil.NoSuchProcess as err:
        disconnect()
        session['terminal_config'] = TERM_INIT_CONFIG
        return
    if child_process.status() not in ('running', 'sleeping'):
        disconnect()
        session['terminal_config'] = TERM_INIT_CONFIG
        return
    # print(session)
    # print(data, 'from input')
    fd = session.get('terminal_config').get('fd')
    if fd:
        # print("writing to ptd: %s" % data["input"])
        # os.write(fd, data["input"].encode('ascii'))
        os.write(fd, data["input"].encode())


@socket_io.on("resize", namespace="/pty")
def resize(data):
    try:
        child_process = psutil.Process(session.get('terminal_config').get('child_pid'))
    except psutil.NoSuchProcess as err:
        disconnect()
        session['terminal_config'] = TERM_INIT_CONFIG
        return
    if child_process.status() not in ('running', 'sleeping'):
        disconnect()
        session['terminal_config'] = TERM_INIT_CONFIG
        return
    fd = session.get('terminal_config').get('fd')
    if fd:
        set_win_size(fd, data["rows"], data["cols"])


@socket_io.on("connect", namespace="/pty")
def pty_connect():
    """new client connected"""

    if session.get('terminal_config', {}).get('child_pid', None):
        print(session['terminal_config']['child_pid'])
        # already started child process, don't start another
        return

    # create child process attached to a pty we can read from and write to
    (child_pid, fd) = pty.fork()
    if child_pid == 0:
        # this is the child process fork.
        # anything printed here will show up in the pty, including the output
        # of this subprocess
        # subprocess.run('bash')
        term_type = session.get('terminal_config').get('term_type')
        path = TERM_INIT_CONFIG.get('client_path', {}).get(term_type, None)
        if not path:
            print("Can't locate {} binary, exit".format(term_type))
            disconnect()
        if term_type == 'telnet':
            # switch to the right location of your telnet binary (example comes from OSX which got telnet from brew)
            # or you can also make work like auto-detection, or manually but configurable
            os.execl(path, 'telnet', '-l', session['terminal_config']['username'],
                     session['terminal_config']['domain'], '{}'.format(session['terminal_config']['port']))
        elif term_type == 'ssh':
            # switch to the right location of your ssh binary
            # or you can also make work like auto-detection, or manually but configurable
            os.execl(path, 'ssh', '-p',
                     '{}'.format(session['terminal_config']['port']),
                     '{}@{}'.format(session['terminal_config']['username'], session['terminal_config']['domain']))
        else:
            app.logger.debug("wrong term type {}".format(term_type))
            disconnect()
            session['terminal_config'] = TERM_INIT_CONFIG
    else:
        # this is the parent process fork.
        # store child fd and pid in session
        # which means different visitor get different pid, fd, and its own room (by default)
        session['terminal_config']['fd'] = fd
        session['terminal_config']['child_pid'] = child_pid
        session['terminal_config']['room_id'] = rooms()[0]
        # in this article https://overiq.com/flask-101/sessions-in-flask/
        # it said that if a mutable data structure need to be set in the flask session
        # we have to use session.modified = True to explicitly let flask know it
        session.modified = True
        set_win_size(fd, 50, 50)
        app.logger.debug("child pid = {}".format(child_pid))
        app.logger.debug("rooms of this session = {}".format(rooms()))
        socket_io.start_background_task(read_and_forward_pty_output, fd, child_pid, rooms()[0])
        app.logger.debug("background task running")
        # print(session)


@socket_io.on('disconnect', namespace='/pty')
def pty_disconnect():
    try:
        child_process = psutil.Process(session.get('terminal_config').get('child_pid'))
    except psutil.NoSuchProcess as err:
        disconnect()
        session['terminal_config'] = TERM_INIT_CONFIG
        return err
    if child_process.status() in ('running', 'sleeping'):
        # if visitor just close the browser tab then left alone the pty here
        # it should be terminated by the parent process after
        child_process.terminate()
        app.logger.debug('user left the pty alone, terminated')
    app.logger.debug('Client disconnected')


if __name__ == '__main__':
    socket_io.run(app, host='0.0.0.0',debug=True, port=9005)
