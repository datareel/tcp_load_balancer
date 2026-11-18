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
# RHEL 8: the RHEL 8 openssl-devel is 1.1.1k. Use the EPEL openssl3-devel
# (OpenSSL 3.5) when it is installed and nothing else was chosen.
if [ "${OS}" = "rhel8" ] && [ -z "${OPENSSL_PKG}" ] && [ -z "${OPENSSL_PREFIX}" ] && \
   pkg-config --exists openssl3 2>/dev/null; then
    export OPENSSL_PKG=openssl3
    echo "RHEL 8: building with pkg-config openssl3 $(pkg-config --modversion openssl3)"
fi
export OPENSSL_PKG OPENSSL_PREFIX
make clean
# OpenSSL 3.5 or later only (the build also stops in src/tls.cpp)
OPENSSL_HDR=$(make -s openssl-check) || {
    echo "ERROR - OpenSSL 3.5 or later headers are required (openssl-devel)."
    echo "ERROR - On RHEL 8 install the EPEL openssl3-devel package (OpenSSL 3.5)."
    exit 1
}
echo "Building with ${OPENSSL_HDR}"
make
if ldd drlb_server | grep -q 'libssl.so.1'; then
    echo "ERROR - drlb_server links an OpenSSL older than 3: $(ldd drlb_server | grep libssl)"
    exit 1
fi

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
install -m 0644 README.md RELEASE_NOTES_2.0.txt RELEASE_NOTES_2.0.1.txt COPYING version.txt etc/example_config.cfg \
    docs/USER_GUIDE.md "${STAGE}/usr/share/doc/drlb/"
gzip -9 -n -c man/drlb_server.8 > "${STAGE}/usr/share/man/man8/drlb_server.8.gz"
gzip -9 -n -c man/drlb_ssl_server.8 > "${STAGE}/usr/share/man/man8/drlb_ssl_server.8.gz"

tar czf "${TOPDIR}/BUILD/drlb_server.tar.gz" -C "${STAGE}" .
cp "${HERE}/drlb_server.spec" "${TOPDIR}/SPECS/"

rpmbuild -bb --define "_topdir ${TOPDIR}" --define "dist ${DIST}" \
    --define "drlb_tarball ${TOPDIR}/BUILD/drlb_server.tar.gz" \
    --buildroot "${TOPDIR}/BUILDROOT" "${TOPDIR}/SPECS/drlb_server.spec"

# The package must require OpenSSL 3.5 libraries and nothing older
RPM=$(ls "${TOPDIR}"/RPMS/x86_64/drlb_server-*.rpm)
if rpm -qpR "${RPM}" | grep -q 'libssl.so.1' || ! rpm -qpR "${RPM}" | grep -q 'libssl.so.3(OPENSSL_3.5.0)'; then
    echo "ERROR - ${RPM} does not require OpenSSL 3.5:"
    rpm -qpR "${RPM}" | grep -E 'ssl|crypto'
    exit 1
fi
echo "OpenSSL in ${RPM##*/}: ${OPENSSL_HDR}, $(ldd drlb_server | grep -oE 'libssl[^ ]*' | head -1)"

mkdir -p "${HOME}/rpmbuild/RPMS/x86_64"
cp -v "${TOPDIR}"/RPMS/x86_64/drlb_server-*.rpm "${HOME}/rpmbuild/RPMS/x86_64/"
rm -rf "${BUILDDIR}"
