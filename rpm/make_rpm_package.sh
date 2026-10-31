#!/bin/bash
# Build the drlb_server RPM on the RHEL version it is for, or in a
# matching UBI container.
#
# Usage: ./make_rpm_package.sh rhel8|rhel9|rhel10 [build_dir]
# Needs: gcc-c++ make rpm-build openssl-devel

set -e
umask 0022

OS=${1,,}
case "${OS}" in
    rhel8) DIST=".el8" ;;
    rhel9) DIST=".el9" ;;
    rhel10) DIST=".el10" ;;
    *) echo "Usage: ${0} rhel8|rhel9|rhel10 [build_dir]"; exit 1 ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "${HERE}/.." && pwd)
BUILDDIR=${2:-/tmp/drlb_build_$(whoami)}
STAGE="${BUILDDIR}/stage"
TOPDIR="${BUILDDIR}/rpmbuild"

rm -rf "${BUILDDIR}"
mkdir -p "${STAGE}" "${TOPDIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cd "${TOP}"
make clean
make

# Stage the files in their installed locations
make install DESTDIR="${STAGE}" PREFIX=/usr
install -d -m 0755 "${STAGE}/etc/drlb" "${STAGE}/etc/drlb/ssl" "${STAGE}/etc/drlb/ssl/certs"
install -d -m 0750 "${STAGE}/etc/drlb/ssl/private" "${STAGE}/var/log/drlb"
install -D -m 0644 etc/drlb_server_sysconfig "${STAGE}/etc/sysconfig/drlb_server"
install -D -m 0644 etc/drlb_ssl_server_sysconfig "${STAGE}/etc/sysconfig/drlb_ssl_server"
install -m 0644 etc/active_configs.list_template "${STAGE}/etc/drlb/active_configs.list"
install -m 0644 etc/http_rr_test.cfg etc/ssl_bridge.cfg "${STAGE}/etc/drlb/"
install -d -m 0755 "${STAGE}/usr/libexec/drlb" "${STAGE}/usr/lib/systemd/system" \
    "${STAGE}/usr/share/doc/drlb" "${STAGE}/usr/share/man/man8"
install -m 0755 systemd/drlb_platform_check systemd/drlb_server_ctl "${STAGE}/usr/libexec/drlb/"
install -m 0644 systemd/drlb_server.service systemd/drlb_server@.service \
    systemd/drlb_ssl_server.service "${STAGE}/usr/lib/systemd/system/"
install -m 0644 README.md RELEASE_NOTES_2.0.txt COPYING version.txt etc/example_config.cfg \
    docs/README_load_balancer_1.60.txt docs/README_ssl_bridge_1.60.txt "${STAGE}/usr/share/doc/drlb/"
gzip -9 -n -c man/drlb_server.8 > "${STAGE}/usr/share/man/man8/drlb_server.8.gz"
gzip -9 -n -c man/drlb_ssl_server.8 > "${STAGE}/usr/share/man/man8/drlb_ssl_server.8.gz"

tar czf "${TOPDIR}/BUILD/drlb_server.tar.gz" -C "${STAGE}" .
cp "${HERE}/drlb_server.spec" "${TOPDIR}/SPECS/"

rpmbuild -bb --define "_topdir ${TOPDIR}" --define "dist ${DIST}" \
    --define "drlb_tarball ${TOPDIR}/BUILD/drlb_server.tar.gz" \
    --buildroot "${TOPDIR}/BUILDROOT" "${TOPDIR}/SPECS/drlb_server.spec"

mkdir -p "${HOME}/rpmbuild/RPMS/x86_64"
cp -v "${TOPDIR}"/RPMS/x86_64/drlb_server-*.rpm "${HOME}/rpmbuild/RPMS/x86_64/"
rm -rf "${BUILDDIR}"
