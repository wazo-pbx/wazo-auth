# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import argparse

from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy
from xivo.xivo_logging import get_log_level_by_name


TWO_HOURS = 60 * 60 * 2
_DEFAULT_HTTP_PORT = 9497
_DEFAULT_CONFIG = {
    'user': 'wazo-auth',
    'config_file': '/etc/wazo-auth/config.yml',
    'extra_config_files': '/etc/wazo-auth/conf.d',
    'log_level': 'info',
    'log_filename': '/var/log/wazo-auth.log',
    'pid_filename': '/var/run/wazo-auth/wazo-auth.pid',
    'default_token_lifetime': TWO_HOURS,
    'token_cleanup_interval': 60.0,
    'enabled_http_plugins': {
        'users': False,
        'policies': True,
    },
    'enabled_backend_plugins': {
        'xivo_admin': True,
        'xivo_service': True,
        'xivo_user': True,
    },
    'backend_policies': {
        'ldap_user': 'wazo_default_user_policy',
        'xivo_admin': 'wazo_default_admin_policy',
        'xivo_user': 'wazo_default_user_policy',
    },
    'rest_api': {
        'max_threads': 25,
        'https': {
            'listen': '0.0.0.0',
            'port': _DEFAULT_HTTP_PORT,
            'certificate': '/usr/share/xivo-certs/server.crt',
            'private_key': '/usr/share/xivo-certs/server.key',
        },
        'cors': {
            'enabled': False,
        },
    },
    'consul': {
        'scheme': 'https',
        'host': 'localhost',
        'port': 8500,
        'verify': '/usr/share/xivo-certs/server.crt',
    },
    'service_discovery': {
        'advertise_address': 'auto',
        'advertise_address_interface': 'eth0',
        'advertise_port': _DEFAULT_HTTP_PORT,
        'enabled': True,
        'ttl_interval': 30,
        'refresh_interval': 27,
        'retry_interval': 2,
        'extra_tags': [],
    },
    'confd': {
        'host': 'localhost',
        'port': 9486,
        'verify_certificate': '/usr/share/xivo-certs/server.crt',
        'https': True,
    },
    'amqp': {
        'uri': 'amqp://guest:guest@localhost:5672/',
        'exchange_name': 'xivo',
        'exchange_type': 'topic',
    },
}


def _parse_cli_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', action='store', help='The path to the config file')
    parser.add_argument('-u', '--user', help='User to run the daemon')
    parser.add_argument('-d', '--debug', action='store_true', help='Log debug messages')
    parser.add_argument('-f', '--foreground', action='store_true', help="Foreground, don't daemonize")
    parser.add_argument('-l',
                        '--log-level',
                        action='store',
                        help="Logs messages with LOG_LEVEL details. Must be one of:\n"
                             "critical, error, warning, info, debug. Default: %(default)s")
    parsed_args = parser.parse_args(argv)

    result = {}
    if parsed_args.config_file:
        result['config_file'] = parsed_args.config_file
    if parsed_args.user:
        result['user'] = parsed_args.user
    if parsed_args.debug:
        result['debug'] = parsed_args.debug
    if parsed_args.foreground:
        result['foreground'] = parsed_args.foreground
    if parsed_args.log_level:
        result['log_level'] = parsed_args.log_level

    return result


def _get_reinterpreted_raw_values(config):
    result = {}

    log_level = config.get('log_level')
    if log_level:
        result['log_level'] = get_log_level_by_name(log_level)

    return result


def get_config(argv):
    cli_config = _parse_cli_args(argv)
    file_config = read_config_file_hierarchy(ChainMap(cli_config, _DEFAULT_CONFIG))
    reinterpreted_config = _get_reinterpreted_raw_values(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    return ChainMap(reinterpreted_config, cli_config, file_config, _DEFAULT_CONFIG)
