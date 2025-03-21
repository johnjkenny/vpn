from argparse import REMAINDER

from vpn.arg_parser import ArgParser


def parse_parent_args(args: dict):
    if args.get('server'):
        return vpn_server(args['server'])
    if args.get('client'):
        return vpn_client(args['client'])
    return True


def vpn_parent():
    args = ArgParser('VPN Commands', None, {
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
    if args.get('enable'):
        return VpnServer().enable_service()
    if args.get('disable'):
        return VpnServer().disable_service()
    if args.get('certs'):
        return vpn_certs(args['certs'])
    if args.get('init'):
        from vpn.init import Init
        return Init(args['port'], args['force']).run_server_init()
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
        },
        'init': {
            'short': 'I',
            'help': 'initialize server service',
            'action': 'store_true'
        },
        'port': {
            'short': 'p',
            'help': 'Port to use for service init. Default is 1194',
            'type': int,
            'default': 1194,
        },
        'force': {
            'short': 'F',
            'help': 'Force action',
            'action': 'store_true',
        },
        'certs': {
            'short': 'c',
            'help': 'Generate client certificates (vpn-certs)',
            'nargs': REMAINDER
        },
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
    if args.get('enable'):
        return VpnClient().enable_service()
    if args.get('disable'):
        return VpnClient().disable_service()
    if args.get('init'):
        from vpn.init import Init
        if not args.get('certs'):
            print('Missing client certificates')
            return False
        return Init(force=args['force']).run_client_init(args['certs'], args['password'])
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
        },
        'init': {
            'short': 'I',
            'help': 'initialize client service',
            'action': 'store_true'
        },
        'certs': {
            'short': 'c',
            'help': 'Client init certificates (.bundle). Provide full path to bundle file',
        },
        'password': {
            'short': 'p',
            'help': 'Password used during cert creation for decryption. Omit to use default cipher',
            'action': 'store_true',
        },
        'force': {
            'short': 'F',
            'help': 'Force action',
            'action': 'store_true',
        }
    }).set_arguments()
    if not parse_client_args(args):
        exit(1)
    exit(0)


def parse_cert_args(args: dict):
    from vpn.vpn_utils import VpnServer
    if args.get('name'):
        return VpnServer().create_and_bundle_client_certs(args['name'], args['password'], args['force'])
    if args.get('delete'):
        return VpnServer().delete_client_cert(args['delete'])
    return True


def vpn_certs(parent_args: list = None):
    args = ArgParser('VPN Client Certs', parent_args, {
        'name': {
            'short': 'n',
            'help': 'Name of client system',
        },
        'password': {
            'short': 'p',
            'help': 'Password to encrypt cert bundle. Omit to use default encryption',
            'action': 'store_true',
        },
        'delete': {
            'short': 'd',
            'help': 'Delete client certificate bundle',
        },
        'force': {
            'short': 'F',
            'help': 'Force action',
            'action': 'store_true',
        }
    }).set_arguments()
    if not parse_cert_args(args):
        exit(1)
    exit(0)
