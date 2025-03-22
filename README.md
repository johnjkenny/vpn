# VPN

This project is a simple VPN service that uses OpenVPN to create a secure tunnel between a server and client.

## Server generates the following certs:
- ca.crt
- ca.key
- server.crt
- server.key
- dh.pem
- tls-crypt.key
- client.crt
- client.key

The server is configured to run on port `1194` by default, but can be set to a different port during initialization.
The server is setup to use `dnscrypt-proxy` to encrypt DNS queries and the client is configured to use the server as the
DNS resolver.


## The client cert bundle includes the following:
- ca.crt
- tls-crypt.key
- client.crt
- client.key
- client.conf

The client bundle is encrypted with the provided password during creation or uses a default embedded encryption key.
The encryption is added to prevent any package sniffing while transferring the bundle to the client (man-in-the-middle).
The certs use `ECDSA-SHA256` keys and `TLSv1.3` `AES-256-GCM-SHA384` cipher for encryption. The client config file includes
the server IP and port to establish connection with server.


### Limitations:
This has been tested with `rocky9.5` with server and client and most likely will not work with other distribution.
Further development will be needed. Feel free to fork and make it work for your needs, submit a PR, or open an issue to
request a feature. The initialization expects firewalld to be installed and running on the server for proper
configuration.


## Server Installation

1. Create virtual Environment
```bash
python3 -m venv venv
```

2. Activate virtual Environment
```bash
source venv/bin/activate
```

3. Install requirements
```bash
pip install -r requirements.txt
```

4. Install console scripts
```bash
pip install -e .
```

5. Initialize the environment
```bash
vpn --server --init

# Set the Certificate Authority subject parameters when prompted (leave blank for default values)
CA Country Name (2 letter code) [US]: 
CA State or Province Name [US-STATE]: 
CA Locality Name (city) [US-CITY]: 
CA Organization Name (eg, company) [US-Company]: 
CA Organizational Unit Name (eg, section) [US-Department]: 
CA email [myEmail@email.com]:
```

6. Generate client cert bundle
```bash
# Use --password (-p) flag to set an encryption password on the bundle or omit to use default encryption key
vpn --server --certs --name vpn-client --password
Enter password: 
[2025-03-21 22:56:24,506][INFO][vpn_utils,267]: Client bundle created: /etc/openvpn/certs/vpn-client.bundle
```

7. Copy the client bundle to the client machine and install the client

8. Repeat steps 6 and 7 for each new client


### Client Installation

1. Create virtual Environment
```bash
python3 -m venv venv
```

2. Activate virtual Environment
```bash
source venv/bin/activate
```

3. Install requirements
```bash
pip install -r requirements.txt
```

4. Install console scripts
```bash
pip install -e .
```

5. Initialize the environment
```bash
# Use --password (-p) flag if a password was set when creating the bundle. Omit to use default encryption key
vpn --client --init --certs /home/my-user/vpn-client.bundle --password
Enter password:
```


## Usage:

### Parent commands:
```bash
$ vpn -h
usage: vpn [-h] [-s ...] [-c ...]

VPN Commands

options:
  -h, --help            show this help message and exit

  -s ..., --server ...  VPN server commands (vpn-server)

  -c ..., --client ...  VPN client commands (vpn-client)

```

### Server Commands:
```bash
$ vpn -s -h
usage: vpn [-h] [-s] [-st] [-S] [-r] [-e] [-d] [-I] [-p PORT] [-F] [-c ...]

VPN Server

options:
  -h, --help            show this help message and exit

  -s, --start           start server service or provide status

  -st, --status         server service status

  -S, --stop            stop server service

  -r, --restart         restart server service

  -e, --enable          enable server service

  -d, --disable         disable server service

  -I, --init            initialize server service

  -p PORT, --port PORT  Port to use for service init. Default is 1194

  -F, --force           Force action

  -c ..., --certs ...   Generate client certificates (vpn-certs)


$ vpn -s -st
● openvpn-server@service.service - OpenVPN service for service
     Loaded: loaded (/usr/lib/systemd/system/openvpn-server@.service; enabled; preset: disabled)
     Active: active (running) since Fri 2025-03-21 22:55:34 UTC; 18min ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
             https://community.openvpn.net/openvpn/wiki/HOWTO
   Main PID: 5004 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 10890)
     Memory: 1.6M
        CPU: 57ms
     CGroup: /system.slice/system-openvpn\x2dserver.slice/openvpn-server@service.service
             └─5004 /usr/sbin/openvpn --status /run/openvpn-server/status-service.log --status-version 2 --suppress-timestamps --cipher AES-256-GCM --data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC --config service.conf

Mar 21 22:55:34 vpn-server systemd[1]: Starting OpenVPN service for service...
Mar 21 22:55:34 vpn-server systemd[1]: Started OpenVPN service for service.
```


### Client Commands:
```bash
$ vpn -c -h
usage: vpn [-h] [-s] [-st] [-S] [-r] [-e] [-d] [-I] [-c CERTS] [-p] [-F]

VPN Client

options:
  -h, --help            show this help message and exit

  -s, --start           start client service or provide status

  -st, --status         client service status

  -S, --stop            stop client service

  -r, --restart         restart client service

  -e, --enable          enable client service

  -d, --disable         disable client service

  -I, --init            initialize client service

  -c CERTS, --certs CERTS
                        Client init certificates (.bundle). Provide full path to bundle file

  -p, --password        Password used during cert creation for decryption. Omit to use default
                        cipher

  -F, --force           Force action

$ vpn -c -st
● openvpn-client@service.service - OpenVPN tunnel for service
     Loaded: loaded (/usr/lib/systemd/system/openvpn-client@.service; enabled; preset: disabled)
     Active: active (running) since Fri 2025-03-21 22:58:18 UTC; 17min ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
             https://community.openvpn.net/openvpn/wiki/HOWTO
   Main PID: 4754 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 10890)
     Memory: 1.5M
        CPU: 47ms
     CGroup: /system.slice/system-openvpn\x2dclient.slice/openvpn-client@service.service
             └─4754 /usr/sbin/openvpn --suppress-timestamps --nobind --config service.conf

Mar 21 22:58:18 vpn-client systemd[1]: Starting OpenVPN tunnel for service...
Mar 21 22:58:18 vpn-client systemd[1]: Started OpenVPN tunnel for service.
```

### Certs Commands:
```bash
$ vpn -s -c -h
usage: vpn [-h] [-n NAME] [-p] [-d DELETE] [-F]

VPN Client Certs

options:
  -h, --help            show this help message and exit

  -n NAME, --name NAME  Name of client system

  -p, --password        Password to encrypt cert bundle. Omit to use default encryption

  -d DELETE, --delete DELETE
                        Delete client certificate bundle

  -F, --force           Force action
```


## Management
- VPN logs can be found `/etc/openvpn/logs` on both server and client machines
- VPN server config can be found `/etc/openvpn/server`
- VPN client config can be found `/etc/openvpn/client`
- VPN certs can be found `/etc/openvpn/certs` on both server and client machines
- A backup of resolve.conf is stored in `/etc/openvpn/bkp.resolv.conf` incase of DNS issues


## dnscrypt-proxy

- `dnscrypt-proxy` is installed on the server only
- The service is `dnscrypt-proxy.service` and you can use systemctl to manage it
- The service is enabled by default and will start on boot
- The configuration file is located at `/etc/dnscrypt-proxy/dnscrypt-proxy.toml`
- The client is configured to use the server as DNS resolver
