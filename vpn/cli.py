from argparse import REMAINDER

from vpn.arg_parser import ArgParser


def parse_parent_args(args: dict):
    if args.get('init'):
        return vpn_init(args['init'])
    if args.get('server'):
        return vpn_server(args['server'])
    if args.get('client'):
        return vpn_client(args['client'])
    if args.get('certs'):
        return vpn_certs(args['certs'])
    return True


def vpn_parent():
    args = ArgParser('VPN Commands', None, {
        'certs': {
            'short': 'C',
            'help': 'Generate client certificates (vpn-certs)',
            'nargs': REMAINDER
        },
        'init': {
            'short': 'I',
            'help': 'Initialize VPN server or client (vpn-init)',
            'nargs': REMAINDER
        },
        'server': {
            'short': 's',
            'help': 'VPN server commands (vpn-server)',
            'nargs': REMAINDER
        },
        'client': {
            'short': 'c',
            'help': 'VPN client commands (vpn-client)',
            'nargs': REMAINDER
        },
    }).set_arguments()
    if not parse_parent_args(args):
        exit(1)
    exit(0)


def parse_init_args(args: dict):
    from vpn.init import Init
    if args.get('server'):
        return Init(args['force'])._run_server_init()
    if args.get('client'):
        return Init(args['force'])._run_client_init()
    return True


def vpn_init(parent_args: list = None):
    # ToDo: implement a generic password for client cert gen encryption is password is provided during server init
    args = ArgParser('VPN Initialization', parent_args, {
        'server': {
            'short': 's',
            'help': 'Run server initialization',
            'action': 'store_true',
        },
        'client': {
            'short': 'c',
            'help': 'Run client initialization',
            'action': 'store_true',
        },
        'ip': {
            'short': 'i',
            'help': 'IP to use for server or client',
        },
        'port': {
            'short': 'p',
            'help': 'Port to use for server or client',
        },
        'password': {
            'short': 'P',
            'help': 'Password to use for client certificate decryption',
        },
        'force': {
            'short': 'F',
            'help': 'Force action',
            'action': 'store_true',
        }
    }).set_arguments()
    if not parse_init_args(args):
        exit(1)
    exit(0)


def parse_server_args(args: dict):
    from vpn.vpn_utils import VpnServer
    if args.get('start'):
        return VpnServer().start_service()
    if args.get('stop'):
        return VpnServer().stop_service()
    if args.get('restart'):
        return VpnServer().restart_service()
    if args.get('status'):
        return VpnServer().get_service_status(True)[1]
    return True


def vpn_server(parent_args: list = None):
    args = ArgParser('VPN Server', parent_args, {
        'start': {
            'short': 's',
            'help': 'start server service or provide status',
            'action': 'store_true',
        },
        'status': {
            'short': 'st',
            'help': 'server service status',
            'action': 'store_true',
        },
        'stop': {
            'short': 'S',
            'help': 'stop server service',
            'action': 'store_true',
        },
        'restart': {
            'short': 'r',
            'help': 'restart server service',
            'action': 'store_true',
        },
        'enable': {
            'short': 'e',
            'help': 'enable server service',
            'action': 'store_true',
        },
        'disable': {
            'short': 'd',
            'help': 'disable server service',
            'action': 'store_true'
        }
    }).set_arguments()
    if not parse_server_args(args):
        exit(1)
    exit(0)


def parse_client_args(args: dict):
    from vpn.vpn_utils import VpnClient
    if args.get('start'):
        return VpnClient().start_service()
    if args.get('stop'):
        return VpnClient().stop_service()
    if args.get('restart'):
        return VpnClient().restart_service()
    if args.get('status'):
        return VpnClient().get_service_status(True)[1]
    return True


def vpn_client(parent_args: list = None):
    args = ArgParser('VPN Client', parent_args, {
        'start': {
            'short': 's',
            'help': 'start client service or provide status',
            'action': 'store_true',
        },
        'status': {
            'short': 'st',
            'help': 'client service status',
            'action': 'store_true',
        },
        'stop': {
            'short': 'S',
            'help': 'stop client service',
            'action': 'store_true',
        },
        'restart': {
            'short': 'r',
            'help': 'restart client service',
            'action': 'store_true',
        },
        'enable': {
            'short': 'e',
            'help': 'enable client service',
            'action': 'store_true',
        },
        'disable': {
            'short': 'd',
            'help': 'disable client service',
            'action': 'store_true'
        }
    }).set_arguments()
    if not parse_client_args(args):
        exit(1)
    exit(0)


def parse_cert_args(args: dict):
    # ToDo: add handling to encrypt client certificate bundle
    from pathlib import Path
    from vpn.vpn_utils import VpnServer
    if args.get('name'):
        cert_auth = VpnServer().certs
        if Path(cert_auth.serial_file).exists():
            return cert_auth.create(args['name'], server=False)
        cert_auth.log('CA serial file does not exist. Certs can only be generated on VPN server')
        return False
    return True


def vpn_certs(parent_args: list = None):
    args = ArgParser('VPN Client Certs', parent_args, {
        'name': {
            'short': 'n',
            'help': 'Name of client system',
        },
        'password': {
            'short': 'P',
            'help': 'Password to encrypt client certificate bundle. Omit if no encryption is desired',
        }
    }).set_arguments()
    if not parse_cert_args(args):
        exit(1)
    exit(0)
