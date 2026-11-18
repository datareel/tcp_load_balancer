#!/bin/bash
# Build the drlb_server RPM on the RHEL version it is for, or in a
# matching UBI container.
#
# Usage: ./make_rpm_package.sh rhel8|rhel8-openssl35|rhel9|rhel10 [build_dir]
# Needs: gcc-c++ make rpm-build openssl-devel
#
# OpenSSL per package (the RHEL 8 pair follows DRCM 1.49):
#   rhel8            drlb_server: RHEL 8 system OpenSSL 1.1.1 (FIPS 140
#                    validated by Red Hat), FIPS build, classic TLS
#   rhel8-openssl35  drlb_server-openssl35: static OpenSSL 3.5
#                    (rpm/build_openssl35.sh first), post-quantum TLS. It
#                    provides and conflicts with drlb_server; switch with
#                    "dnf swap drlb_server drlb_server-openssl35"
#   rhel9, rhel10    drlb_server: system OpenSSL 3.5, post-quantum TLS

set -e
umask 0022

OS=${1,,}
FLAVOR=system35
NAME=drlb_server
case "${OS}" in
    rhel8) DIST=".el8"; FLAVOR=fips ;;
    rhel8-openssl35) DIST=".el8"; FLAVOR=static35; NAME=drlb_server-openssl35 ;;
    rhel9) DIST=".el9" ;;
    rhel10) DIST=".el10" ;;
    *) echo "Usage: ${0} rhel8|rhel8-openssl35|rhel9|rhel10 [build_dir]"; exit 1 ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "${HERE}/.." && pwd)
BUILDDIR=${2:-/tmp/drlb_build_$(whoami)}
STAGE="${BUILDDIR}/stage"
TOPDIR="${BUILDDIR}/rpmbuild"

rm -rf "${BUILDDIR}"
mkdir -p "${STAGE}" "${TOPDIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cd "${TOP}"
MAKE_ARGS=()
case "${FLAVOR}" in
    fips) MAKE_ARGS=(FIPS_BUILD=1) ;;
    static35)
        OPENSSL35_PREFIX=${OPENSSL35_PREFIX:-/opt/openssl-3.5}
        if [ ! -f "${OPENSSL35_PREFIX}/lib64/libssl.a" ]; then
            echo "ERROR - No static OpenSSL 3.5 in ${OPENSSL35_PREFIX}; run rpm/build_openssl35.sh first"
            exit 1
        fi
        MAKE_ARGS=(OPENSSL_PREFIX="${OPENSSL35_PREFIX}" OPENSSL_STATIC=1) ;;
esac
make clean
# OpenSSL 3.5 or later, except the RHEL 8 FIPS build (1.1.1); the build
# also stops in src/tls.cpp
OPENSSL_HDR=$(make -s "${MAKE_ARGS[@]}" openssl-check) || {
    echo "ERROR - The OpenSSL headers are too old for ${OS}."
    echo "ERROR - RHEL 8: use rhel8 (FIPS build, system OpenSSL) or rhel8-openssl35."
    exit 1
}
echo "Building ${NAME} (${FLAVOR}) with ${OPENSSL_HDR}"
make "${MAKE_ARGS[@]}"
LINKED=$(./drlb_server --version | grep '^Linked with:')
echo "drlb_server ${LINKED}"
case "${FLAVOR}" in
    fips)
        readelf -d drlb_server | grep -q 'NEEDED.*libssl.so.1.1' || { echo "ERROR - the rhel8 package must link the system OpenSSL 1.1.1"; exit 1; }
        echo "${LINKED}" | grep -q 'FIPS build' || { echo "ERROR - not a FIPS build"; exit 1; } ;;
    static35)
        if readelf -d drlb_server | grep -q 'NEEDED.*lib\(ssl\|crypto\)'; then
            echo "ERROR - the openssl35 package must not link a shared libssl/libcrypto"; exit 1
        fi
        readelf -d drlb_server | grep -qE 'RPATH|RUNPATH' && { echo "ERROR - the openssl35 package must have no rpath"; exit 1; }
        echo "${LINKED}" | grep -q 'OpenSSL 3\.5\..*, static, ' || { echo "ERROR - not a static OpenSSL 3.5 build"; exit 1; } ;;
    *)
        if readelf -d drlb_server | grep -q 'libssl.so.1'; then
            echo "ERROR - drlb_server links an OpenSSL older than 3: $(ldd drlb_server | grep libssl)"
            exit 1
        fi ;;
esac

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
if [ "${FLAVOR}" = "static35" ]; then
    # Provides/Conflicts go after Release:, where %{version} and %{release} are defined
    sed -i -e 's/^Name: drlb_server$/Name: drlb_server-openssl35/' \
           -e 's/^\(Release: .*\)$/\1\nProvides: drlb_server = %{version}-%{release}\nConflicts: drlb_server/' \
           -e 's/^Summary: .*/Summary: DRLB TCP and SSL\/TLS load balancer, OpenSSL 3.5 static build (post-quantum TLS)/' \
           "${TOPDIR}/SPECS/drlb_server.spec"
    grep -q '^Name: drlb_server-openssl35' "${TOPDIR}/SPECS/drlb_server.spec" || { echo "ERROR - spec Name not changed"; exit 1; }
fi

# The RPM header records the build host. Use a neutral name so the name
# of the machine that built the release never ends up in the package.
DRLB_BUILDHOST=${DRLB_BUILDHOST:-datareel-build}
rpmbuild -bb --define "_topdir ${TOPDIR}" --define "dist ${DIST}" \
    --define "_buildhost ${DRLB_BUILDHOST}" --define "drlb_openssl ${FLAVOR}" \
    --define "drlb_tarball ${TOPDIR}/BUILD/drlb_server.tar.gz" \
    --buildroot "${TOPDIR}/BUILDROOT" "${TOPDIR}/SPECS/drlb_server.spec"

# The package's OpenSSL requirements must match its flavor
RPM=$(ls "${TOPDIR}"/RPMS/x86_64/${NAME}-2*.rpm)
REQ=$(rpm -qpR "${RPM}")
case "${FLAVOR}" in
    fips) echo "${REQ}" | grep -q 'libssl.so.1.1' || { echo "ERROR - ${RPM} does not require the system OpenSSL 1.1.1"; exit 1; } ;;
    static35) if echo "${REQ}" | grep -qE '^(libssl|libcrypto|openssl)'; then
                  echo "ERROR - ${RPM} requires a shared OpenSSL:"; echo "${REQ}" | grep -E 'ssl|crypto'; exit 1
              fi ;;
    *) if echo "${REQ}" | grep -q 'libssl.so.1' || ! echo "${REQ}" | grep -q 'libssl.so.3(OPENSSL_3.5.0)'; then
           echo "ERROR - ${RPM} does not require OpenSSL 3.5:"; echo "${REQ}" | grep -E 'ssl|crypto'; exit 1
       fi ;;
esac
if [ "$(rpm -qp --qf '%{BUILDHOST}' "${RPM}")" != "${DRLB_BUILDHOST}" ]; then
    echo "ERROR - ${RPM} build host is not ${DRLB_BUILDHOST}"
    exit 1
fi
echo "OpenSSL in ${RPM##*/}: ${OPENSSL_HDR}, ${FLAVOR}, ${LINKED}"

mkdir -p "${HOME}/rpmbuild/RPMS/x86_64"
cp -v "${RPM}" "${HOME}/rpmbuild/RPMS/x86_64/"
rm -rf "${BUILDDIR}"
