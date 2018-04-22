import argparse
import logging
import socket
import json

import paramiko
from paramiko import AuthenticationException
from paramiko.ssh_exception import NoValidConnectionsError


class Provision:
    def __init__(self, current_private_key, key_json, host_json):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.load_system_host_keys()
        self.log = logging
        self.log.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

        try:
            self.keys = json.load(open(key_json))
        except IOError:
            self.log.warning(
                "Can't seem to find the file: {}. Please provide a valid json key file location.".format(key_json))
        try:
            self.hosts = json.load(open(host_json))
        except IOError:
            self.log.warning(
                "Can't seem to find the file: {}. Please provide a valid json hosts file location.".format(host_json))
        try:
            self.current_private_key = current_private_key
        except IOError:
            self.log.warning(
                "Can't seem to find the file: {}. Please provide the machine private key location.".format(
                    current_private_key))

    def connect(self):
        def cmd_for_keys():
            users_keys = ''
            for user, public_key in self.keys.iteritems():
                users_keys += '#{user}\n{key}\n\n'.format(user=user, key=public_key)

            return {'cmd': 'echo "# Authorized_keys\n\n{keys}\n\n"> ~/.ssh/authorized_keys'.format(keys=users_keys)}

        try:
            cmd_dict = cmd_for_keys()

            for name, instance in self.hosts.iteritems():
                try:
                    self.ssh_client.connect(instance['host'], username=instance['user'],
                                            key_filename=self.current_private_key)
                    self.ssh_client.exec_command(cmd_dict['cmd'])
                    self.ssh_client.close()
                    self.log.info('Manage to provision keys to host {}'.format(name))

                except (AuthenticationException, NoValidConnectionsError) as e:
                    self.log.error('Failed to connect to host:{} Error:{}'.format(name, e))

                except socket.error as e:
                    self.log.error('Connection timeout to host:{} Error:{}'.format(name, e))

                except paramiko.ssh_exception.BadHostKeyException as e:
                    self.log.error('Failed to connect to host, invalid host key! Error:{}'.format(e))
        except AttributeError:
            self.log.error('Please check you provided all the required attributes (SEE --help)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Provision ssh keys from a JSON to bulk of instances.')
    parser.add_argument('-i', '--identity_file', metavar='identity file',
                        help='Location of the machine identity file(private key)', required=True)
    parser.add_argument('-k', '--keys_file', metavar='keys file',
                        help='Set the location for the key json file(default in the same folder)', required=False)
    parser.add_argument('-s', '--hosts_file', metavar='hosts files',
                        help='Set the location for the hosts json file(default in the same folder)', required=False)
    args = vars(parser.parse_args())

    Provision(current_private_key=args.get('identity_file'),
              key_json=args.get('keys_file') if args.get('keys_file') else 'keys.json',
              host_json=args.get('hosts_file') if args.get('hosts_file') else 'hosts.json').connect()
