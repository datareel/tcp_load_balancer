README file for DRLB SSL Bridge 1.60 beta
Last Modified: 10/25/2026

Contents:
--------
* Overview
* RPM Install
* Building and installing from source
* Setting up the SSL bridge service
* SSL certificates
* Self-signed SSL certificates
* SSL encryption protocol
* Regression tests
* Remaining work on this project
* Support and Bug Tracking

Overview
--------
The DRLB SSL bridge is used to decrypt incoming SSL traffic on TCP
port 443 and send encrypted or unencrypted traffic to back-end web
servers. 

Load balancing SSL connections cannot forward IP address information
HTTP headers unless the SSL traffic is decrypted and re-encrypted with
the connection information inserted into the HTTP headers. The DRLB
SSL bridge has options to load balance front-end connections as an
HTTPS server and distribute web traffic to back-end HTTP or HTTPS
servers.

Decrypting front-end SSL traffic and re-encrypting allows you to
forward IP address information to back-end HTTPS servers. Both the
front-end and back-end web traffing remains encrypted during
transport.     

Sending decrypted SSL to back-end web servers over TCP port 80 allows
you to use existing back-end HTTP web services. The load balanced
front-end remains encrypted. The back-end web services can utilize
existing web configurations with having to be reconfigured to run SSL.  

RPM Install
-----------
System administrators, follow the instructions below to build an RPM
for distribution. Build each RPM on the RHEL version it is for, or in
a matching UBI container. RHEL 9 and RHEL 10 are supported. RHEL 8 is
supported only with NetworkManager and firewalld. RHEL 6 and RHEL 7
are no longer supported. The build needs these packages:

# dnf -y install gcc-c++ make rpm-build openssl-devel

$ cd $HOME; mkdir -pv git; cd $HOME/git
$ wget https://datareel.com/downloads/drlb/ssl-bridge-<version>.tar.gz
$ tar xzf ssl-bridge-<version>.tar.gz
$ mv ssl-bridge-<version> ssl-bridge
$ cd ${HOME}/git/ssl-bridge/rpm_builder

RHEL 10:
$ ./make_ssl_rpm_package.sh rhel10
$ sudo dnf -y install ${HOME}/rpmbuild/RPMS/x86_64/drlb_ssl_server-*.el10.x86_64.rpm

RHEL 9:
$ ./make_ssl_rpm_package.sh rhel9
$ sudo dnf -y install ${HOME}/rpmbuild/RPMS/x86_64/drlb_ssl_server-*.el9.x86_64.rpm

RHEL 8 (NetworkManager and firewalld only):
$ ./make_ssl_rpm_package.sh rhel8
$ sudo dnf -y install ${HOME}/rpmbuild/RPMS/x86_64/drlb_ssl_server-*.el8.x86_64.rpm

Useful RPM command to verify package contents:

List package: rpm -qf /usr/sbin/drlb_ssl_server
List files: rpm -ql drlb_ssl_server
List configs: rpm -qc drlb_ssl_server
List docs: rpm -qd drlb_ssl_server

To remove package:

$ sudo dnf -y remove drlb_ssl_server

Building and installing from source
-----------------------------------
Follow the instructions below to build and install the DRLB SSL bridge
from source code: 

$ cd $HOME
$ mkdir -pv git
$ cd $HOME/git
$ wget https://datareel.com/downloads/drlb/ssl-bridge-<version>.tar.gz
$ tar xzf ssl-bridge-<version>.tar.gz
$ mv ssl-bridge-<version> ssl-bridge
$ source $HOME/git/ssl-bridge/env/gnu_env.sh
$ cd $HOME/git/ssl-bridge/ssl_bridge
$ make
$ sudo make install_root

Setting up the SSL bridge service
---------------------------------
The default LB configuration file for the SSL bridge is:

/etc/drlb/ssl_bridge.cfg

In the LB configuration file, refer to the following section for all
settings specific to the SSL config: 

[SSLCONFIG]
# TLS 1.2 and TLS 1.3
ssl_protocol = TLS
ssl_key_file = /etc/drlb/ssl/private/ca.key
ssl_cert_file =  /etc/drlb/ssl/certs/ca.crt
ssl_handshake_timeout_secs = 30
#ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20
#ssl_ciphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
#ssl_use_dhparms = 0
#ssl_dhparms_file =  /etc/drlb/ssl/certs/dhparams.pem
#ssl_encrypt_backend = 0
#ssl_backend_hostname = www.example.com
#ssl_verify_backend_cert = 1
#ssl_backend_ca_list_file = /etc/pki/tls/certs/ca-bundle.crt

By default back-end traffic is set to unencrypted, HTTP. With
ssl_encrypt_backend = 1 the bridge connects to the back-end servers
with TLS and verifies their certificates during the handshake. The
certificate must be issued by a CA in ssl_backend_ca_list_file (the
system trust store when it is not set) and its subjectAltName must
match ssl_backend_hostname, or the node hostname or IP address when
ssl_backend_hostname is not set. The same name is sent to the back-end
server as the TLS server name (SNI). Set ssl_verify_backend_cert = 0
only for test back-end servers with self-signed certificates.

Ciphers follow the system crypto policy, set with
update-crypto-policies. Use ssl_cipher_list (TLS 1.2) and
ssl_ciphersuites (TLS 1.3) only to restrict them further.

For all other DRLB setting please refer to the DRLB README file:

# more /usr/share/doc/drlb_ssl_bridge/README.txt 

or online: 

http://datareel.com/drlb/

The default LB scheme used with the SSL bridge is round robin.

After setting up your LB and SSL config, start the
service:

# systemctl start drlb_ssl_server
# systemctl status drlb_ssl_server

Server messages go to the systemd journal:

# journalctl -u drlb_ssl_server

To watch the log file:

# tail -f /var/log/drlb/ssl_bridge.log

To watch LB stats:

# tail -n 25 -f /var/log/drlb/ssl_bridge_stats.log

To make the LB service persistent: 

# systemctl enable drlb_ssl_server

SSL certificates
----------------
Before starting the SSL bridge you must install or set the location to
your private key and certificate file:

# vi /etc/drlb/ssl_bridge.cfg

[SSLCONFIG]
...
ssl_key_file = /etc/drlb/ssl/private/ca.key
ssl_cert_file =  /etc/drlb/ssl/certs/ca.crt
ssl_use_dhparms = 1
ssl_dhparms_file =  /etc/drlb/ssl/certs/dhparams.pem

If you do not have an SSL certificate issued and verified by a trusted
Certificate Authority you can use a self-signed certificate for
non-production or internal HTTPS services. 

Self-signed SSL certificates
----------------------------
Follow the instructions below to create a self-signed certificate for
non-production or internal HTTPS services:

# mkdir -pv /etc/drlb/ssl/private /etc/drlb/ssl/certs
# openssl dhparam -out /etc/drlb/ssl/certs/dhparams.pem 2048
# openssl genrsa -out /etc/drlb/ssl/private/ca.key  2048
# chgrp drlb /etc/drlb/ssl/private/ca.key
# chmod 640 /etc/drlb/ssl/private/ca.key

# openssl req -new -key /etc/drlb/ssl/private/ca.key -out /etc/drlb/ssl/certs/ca.csr

Country Name (2 letter code) [XX]:
State or Province Name (full name) []:
Locality Name (eg, city) [Default City]:
Organization Name (eg, company) [Default Company Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:
Email Address []: 

# openssl x509 -req -days 365 -in /etc/drlb/ssl/certs/ca.csr -signkey /etc/drlb/ssl/private/ca.key -out /etc/drlb/ssl/certs/ca.crt -extfile <(echo "subjectAltName=DNS:www.example.com")

Replace www.example.com with the name clients use. Clients check the
subjectAltName, not the Common Name.

The server runs as the drlb user, so the private key must be readable
by the drlb group. Keep it unreadable by other users.

# vi /etc/drlb/ssl_bridge.cfg

[SSLCONFIG]
...
ssl_key_file = /etc/drlb/ssl/private/ca.key
ssl_cert_file =  /etc/drlb/ssl/certs/ca.crt
ssl_use_dhparms = 1
ssl_dhparms_file =  /etc/drlb/ssl/certs/dhparams.pem

SSL encryption protocol
-----------------------
The TLS protocol versions are set by the ssl_protocol setting in the
SSLCONFIG section in the LB configuration file: 

[SSLCONFIG]
...
ssl_protocol = TLS

TLS - TLS 1.2 and TLS 1.3 (default)
TLSv1_2 - TLS 1.2 only
TLSv1_3 - TLS 1.3 only

SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are no longer supported, and the
SSLv23 setting from earlier versions is a configuration error. On RHEL
the system crypto policy can raise the minimum further.

Regression tests
----------------
After building, run the regression tests from the top of the source
tree. They start local test servers on 127.0.0.1 and need only Python 3
(and the openssl command for the SSL bridge):

$ python3 tests/ssl_bridge_tests.py

The tests cover load balancing, fail over, timeouts, shutdown and the
security fixes in this release. Each prints PASS or FAIL per check and
exits non-zero if any check fails.

Remaining work on this project
------------------------------

Support and Bug Tracking
------------------------

https://datareel.com/contact.php

