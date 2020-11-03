"""
# coding:utf-8
@Time    : 2020/11/03
@Author  : jiangwei
@mail    : jiangwei1@kylinos.cn
@File    : setting.py
@Software: PyCharm
"""
TERM_INIT_CONFIG = {
    # instead of local server running this web terminal service
    # "domain" is the target that you want to access through local server (with this web terminal)
    # and before doing so - make sure you have username and port (on the "domain") to implement remote access
    'domain': '139.155.232.33',  # or ip address like 192.168.10.11
    'client_path': {
        'telnet': '/usr/bin/telnet',  # confirmed location of your client binary (with cmd like 'which telnet')
        'ssh': '/usr/bin/ssh'
    }
}


class BaseConfig:
    SECRET_KEY = 'ao21nM2ffdgo'
    SESSION_TYPE = 'filesystem'

