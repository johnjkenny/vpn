from setuptools import setup


try:
    setup(
        name='vpn',
        version='1.0.0',
        include_package_data=True,
        package_data={'vpn': []},
        entry_points={'console_scripts': [
            'vpn = vpn.cli:vpn_parent',
            'vpn-init = vpn.cli:vpn_init',
            'vpn-server = vpn.cli:vpn_server',
            'vpn-client = vpn.cli:vpn_client',
            'vpn-certs = vpn.cli:vpn_certs',
        ]},
    )
    exit(0)
except Exception as error:
    print(f'Failed to setup package: {error}')
    exit(1)
