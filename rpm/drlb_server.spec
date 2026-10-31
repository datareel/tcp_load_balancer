BuildArch: x86_64
Name: drlb_server
Version: 2.0
Release: 1%{?dist}
Summary: DRLB TCP and SSL/TLS load balancer
Group: System Environment/Daemons
License: GPL
Distribution: Datareel Open Source
URL: https://datareel.com/drlb
Vendor: Datareel Open Source
Requires: openssl-libs
Requires: systemd
Requires: bash
Requires(pre): shadow-utils
Recommends: NetworkManager
Recommends: firewalld
# 2.0 replaces both 1.60 packages
Obsoletes: drlb_ssl_server < 2.0
Provides: drlb_ssl_server = %{version}-%{release}

%description
The DataReel load balancer (DRLB) is a software based TCP load
balancer. It accepts high volumes of TCP connections and distributes
them to multiple back end servers. A configuration with an [SSLCONFIG]
section also terminates SSL/TLS (the DRLB SSL bridge), with optional
TLS to the back end servers. Version 2.0 combines the drlb_server and
drlb_ssl_server packages and no longer uses the DataReel library.

%install
tar xf %{drlb_tarball} -C $RPM_BUILD_ROOT

%files
%dir %attr(0755, root, root) "/etc/drlb"
%dir %attr(0755, root, root) "/etc/drlb/ssl"
%dir %attr(0750, root, drlb) "/etc/drlb/ssl/private"
%dir %attr(0755, root, root) "/etc/drlb/ssl/certs"
%dir %attr(0750, drlb, drlb) "/var/log/drlb"
%attr(0755, root, root) "/usr/sbin/drlb_server"
"/usr/sbin/drlb_ssl_server"
%config(noreplace) %attr(0644, root, root) "/etc/sysconfig/drlb_server"
%config(noreplace) %attr(0644, root, root) "/etc/sysconfig/drlb_ssl_server"
%config(noreplace) %attr(0644, root, root) "/etc/drlb/active_configs.list"
%config %attr(0644, root, root) "/etc/drlb/http_rr_test.cfg"
%config(noreplace) %attr(0644, root, root) "/etc/drlb/ssl_bridge.cfg"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/README.md"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/RELEASE_NOTES_2.0.txt"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/README_load_balancer_1.60.txt"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/README_ssl_bridge_1.60.txt"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/COPYING"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/version.txt"
%doc %attr(0644, root, root) "/usr/share/doc/drlb/example_config.cfg"
%doc %attr(0644, root, root) "/usr/share/man/man8/drlb_server.8.gz"
%doc %attr(0644, root, root) "/usr/share/man/man8/drlb_ssl_server.8.gz"
%attr(0644, root, root) "/usr/lib/systemd/system/drlb_server.service"
%attr(0644, root, root) "/usr/lib/systemd/system/drlb_server@.service"
%attr(0644, root, root) "/usr/lib/systemd/system/drlb_ssl_server.service"
%dir %attr(0755, root, root) "/usr/libexec/drlb"
%attr(0755, root, root) "/usr/libexec/drlb/drlb_platform_check"
%attr(0755, root, root) "/usr/libexec/drlb/drlb_server_ctl"

%pre -p /bin/sh

# The servers run as the drlb system user
getent group drlb >/dev/null || groupadd -r drlb
getent passwd drlb >/dev/null || useradd -r -g drlb -d /var/log/drlb -s /sbin/nologin -c "DataReel load balancer" drlb

# Removing the obsoleted 1.60 drlb_ssl_server package disables and stops
# its service. Remember its state so %posttrans can restore it.
mkdir -p /var/lib/rpm-state/drlb
rm -f /var/lib/rpm-state/drlb/ssl_enabled /var/lib/rpm-state/drlb/ssl_active
# Only the 1.60 drlb_ssl_server package installs this file
if [ -f /usr/share/doc/drlb_ssl_bridge/version.txt ]; then
    systemctl is-enabled --quiet drlb_ssl_server.service 2>/dev/null && touch /var/lib/rpm-state/drlb/ssl_enabled
    systemctl is-active --quiet drlb_ssl_server.service 2>/dev/null && touch /var/lib/rpm-state/drlb/ssl_active
fi
exit 0

%post -p /bin/sh

if [ $1 -eq 1 ] ; then
    # Initial installation
    systemctl preset drlb_server.service drlb_ssl_server.service >/dev/null 2>&1 || :
fi

%preun -p /bin/sh

if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    systemctl --no-reload disable drlb_server.service drlb_ssl_server.service > /dev/null 2>&1 || :
    systemctl stop drlb_server.service drlb_ssl_server.service > /dev/null 2>&1 || :
fi

%postun -p /bin/sh

systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    systemctl try-restart drlb_server.service drlb_ssl_server.service >/dev/null 2>&1 || :
fi

%posttrans -p /bin/sh

systemctl daemon-reload >/dev/null 2>&1 || :
if [ -f /var/lib/rpm-state/drlb/ssl_enabled ]; then
    systemctl enable drlb_ssl_server.service >/dev/null 2>&1 || :
fi
if [ -f /var/lib/rpm-state/drlb/ssl_active ]; then
    systemctl restart drlb_ssl_server.service >/dev/null 2>&1 || :
fi
rm -rf /var/lib/rpm-state/drlb
exit 0

%changelog
* Sat Oct 31 2026 Datareel <datareel.com>
- Version 2.0
- drlb_server and drlb_ssl_server combined in one program and package
- Rewritten in C++17 without the DataReel library
- A config with an [SSLCONFIG] section runs as the SSL bridge
- drlb_ssl_server is a link to drlb_server
- RHEL 8, RHEL 9 and RHEL 10 builds; RHEL 8 only with NetworkManager and firewalld
* Mon Oct 26 2026 Datareel <datareel.com>
- Version 1.60 beta
- Security fixes from the October 2026 review, new poll() based relay
- DataReel 6.2 library update
- RHEL 9 and RHEL 10 builds; RHEL 8 only with NetworkManager and firewalld
- RHEL 6 and RHEL 7 support removed
- Native systemd units in /usr/lib/systemd/system, SysV init script removed
- Servers run as the drlb user with systemd sandboxing
* Mon Feb 05 2024 Datareel <datareel.com>
- Updates for RHEL 8 and RHEL 9 builds
* Wed Oct 19 2016 Datareel <datareel.com>
- Fix for potential ABRT exit from safe_close call on closed file descriptor
* Sun Oct 02 2016 Datareel <datareel.com>
- Initial RPM build
