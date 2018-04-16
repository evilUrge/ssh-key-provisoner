from sys import argv
import logging
import socket
import json

import paramiko
from paramiko import AuthenticationException
from paramiko.ssh_exception import NoValidConnectionsError


class CMD:
    def __init__(self, app_name, *args):

        self.arguments = {}
        for value in args:
            self.arguments[value] = False

        print '{LEN}\n{APP}\n{LEN}'.format(LEN='*' * len(app_name), APP=app_name)
        for x in range(1, (len(argv)), 2):
            if argv[x] in self.arguments:
                self.arguments[argv[x]] = argv[x + 1]


class Provision:
    def __init__(self, current_private_key):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.load_system_host_keys()
        self.log = logging

        self.keys = json.load(open('keys.json'))
        self.hosts = json.load(open('hosts.json'))
        self.current_private_key = current_private_key

    def cmd_for_keys(self):
        users_keys = ''
        for user, public_key in self.keys.iteritems():
            users_keys += '#{user}\n{key}\n\n'.format(user=user, key=public_key)

        return {'cmd': 'echo "# ZZ Authorized_keys\n\n{keys}\n\n"> ~/.ssh/authorized_keys'.format(keys=users_keys)}

    def connect(self):
        cmd_dict = self.cmd_for_keys()

        for name, instance in self.hosts.iteritems():
            try:
                self.ssh_client.connect(instance['host'], username=instance['user'],
                                        key_filename=self.current_private_key)
                self.ssh_client.exec_command(cmd_dict['cmd'])
                self.ssh_client.close()
                print('Manage to provision keys to host {}'.format(name))
                self.log.info('Manage to provision keys to host {}'.format(name))

            except (AuthenticationException, NoValidConnectionsError) as e:
                self.log.error('Failed to connect to host:{} Error:{}'.format(name, e))

            except socket.error as e:
                self.log.error('Connection timeout to host:{} Error:{}'.format(name, e))

            except paramiko.ssh_exception.BadHostKeyException as e:
                self.log.error('Failed to connect to host, invalid host key! Error:{}'.format(e))


if __name__ == '__main__':
    private_key = CMD('Provision keys', '-i').arguments.get('-i')

    if private_key:
        Provision(current_private_key=private_key).connect()
    else:
        print 'Please provide your private key with -i arg'
