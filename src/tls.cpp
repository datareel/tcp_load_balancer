// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// SSL/TLS with OpenSSL: the frontend server context, the backend client
// context, and the per connection handshakes. TLS 1.2 and 1.3 only,
// ciphers from the system crypto policy, backend certificates verified
// by default.
//
// 2.0.1: OpenSSL 3.5 LTS or later is required at build and run time.
// Key exchange groups and signature algorithms are set by DRLB with the
// hybrid post-quantum ML-KEM groups first (X25519MLKEM768), because the
// RHEL 8 and RHEL 9 crypto policies do not offer ML-KEM. ssl_groups and
// ssl_sigalgs = system keep the crypto policy lists.

#include "drlb.h"

#include <cstdio>
#include <filesystem>
#include <sstream>

#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <openssl/objects.h>
#include <openssl/crypto.h>

// OpenSSL 3.5 LTS or later: hybrid ML-KEM key exchange and ML-DSA
// certificates need 3.5. RHEL 9 and 10 use the system OpenSSL 3.5; the
// RHEL 8 drlb_server-openssl35 package links a static OpenSSL 3.5
// (rpm/build_openssl35.sh, make OPENSSL_PREFIX=... OPENSSL_STATIC=1).
//
// The one exception is the RHEL 8 FIPS build (make FIPS_BUILD=1, the
// RHEL 8 drlb_server package): it links the RHEL 8 system OpenSSL 1.1.1,
// which Red Hat validated for FIPS 140, and has no post-quantum TLS.
#if defined(DRLB_FIPS_BUILD)
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "The DRLB FIPS build needs the system OpenSSL 1.1.1 or later headers."
#endif
#define DRLB_MIN_OPENSSL 0x10101000UL
#else
#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "DRLB needs OpenSSL 3.5 or later headers. On RHEL 8 build the static OpenSSL 3.5 (rpm/build_openssl35.sh, make OPENSSL_PREFIX=/opt/openssl-3.5 OPENSSL_STATIC=1) or the FIPS build on the system OpenSSL (make FIPS_BUILD=1)."
#endif
#define DRLB_MIN_OPENSSL 0x30500000UL
#endif

#ifndef DRLB_OPENSSL_FLAVOR
#define DRLB_OPENSSL_FLAVOR "system"
#endif

namespace drlb {

static std::string ssl_error_string()
{
  std::string out;
  unsigned long e;
  while((e = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    if(!out.empty()) out += "; ";
    out += buf;
  }
  return out;
}

static int set_ssl_ciphers(SSL_CTX *ctx)
{
  const SSLConfig &ssl = cfg.ssl;
  if(!ssl.ssl_cipher_list.empty() && SSL_CTX_set_cipher_list(ctx, ssl.ssl_cipher_list.c_str()) != 1) {
    nt_print("ERROR - Bad ssl_cipher_list:", ssl.ssl_cipher_list.c_str());
    return 1;
  }
  if(!ssl.ssl_ciphersuites.empty() && SSL_CTX_set_ciphersuites(ctx, ssl.ssl_ciphersuites.c_str()) != 1) {
    nt_print("ERROR - Bad ssl_ciphersuites:", ssl.ssl_ciphersuites.c_str());
    return 1;
  }
  return 0;
}

// Default key exchange groups, in OpenSSL 3.5 tuple syntax. The first
// tuple holds the hybrid post-quantum groups, so a server picks one of
// them whenever the client supports it (with a HelloRetryRequest if the
// client sent only a classical key share). The "*" groups get a key
// share in the client hello: X25519MLKEM768 and X25519, so a backend
// without ML-KEM still completes in one round trip. "?" skips a group
// the provider does not have (for example in FIPS mode).
const char *DefaultGroups =
  "?*X25519MLKEM768:?SecP256r1MLKEM768:?SecP384r1MLKEM1024"
  "/?*X25519:?secp256r1:?X448:?secp384r1:?secp521r1"
  "/?ffdhe2048:?ffdhe3072";

// Default signature algorithms: ML-DSA (FIPS 204) first, then the
// classical algorithms of the RHEL DEFAULT crypto policy. Needed so a
// server or backend with an ML-DSA certificate works on RHEL 8 and 9.
const char *DefaultSigalgs =
  "?mldsa65:?mldsa87:?mldsa44"
  ":?ecdsa_secp256r1_sha256:?ecdsa_secp384r1_sha384:?ecdsa_secp521r1_sha512"
  ":?ed25519:?ed448"
  ":?rsa_pss_pss_sha256:?rsa_pss_pss_sha384:?rsa_pss_pss_sha512"
  ":?rsa_pss_rsae_sha256:?rsa_pss_rsae_sha384:?rsa_pss_rsae_sha512"
  ":?rsa_pkcs1_sha256:?rsa_pkcs1_sha384:?rsa_pkcs1_sha512";

// Returns 0 if the running OpenSSL library is new enough: 3.5 or later,
// or 1.1.1 or later for the FIPS build. The headers are checked at build
// time; this catches an older shared library.
int check_openssl_version()
{
  if(OpenSSL_version_num() < DRLB_MIN_OPENSSL) {
#if defined(DRLB_FIPS_BUILD)
    nt_print("ERROR - The DRLB FIPS build needs OpenSSL 1.1.1 or later, the library is", OpenSSL_version(OPENSSL_VERSION));
#else
    nt_print("ERROR - DRLB needs OpenSSL 3.5 or later, the library is", OpenSSL_version(OPENSSL_VERSION));
    nt_print("ERROR - On RHEL 8 install the drlb_server-openssl35 package (OpenSSL 3.5 built in)");
#endif
    return 1;
  }
  return 0;
}

// True if the system or OpenSSL is in FIPS mode
bool fips_mode()
{
  FILE *fp = fopen("/proc/sys/crypto/fips_enabled", "r");
  if(fp) {
    int c = fgetc(fp);
    fclose(fp);
    if(c == '1') return true;
  }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return EVP_default_properties_is_fips_enabled(nullptr) == 1;
#else
  return FIPS_mode() != 0;
#endif
}

// True if this build has the post-quantum TLS algorithms
bool pqc_build()
{
#if defined(DRLB_FIPS_BUILD)
  return false;
#else
  return true;
#endif
}

// The OpenSSL the program runs with, for --version and the log
std::string openssl_build_info()
{
  std::string s = std::string("Linked with: ") + OpenSSL_version(OPENSSL_VERSION) + ", " + DRLB_OPENSSL_FLAVOR;
#if defined(DRLB_FIPS_BUILD)
  s += ", FIPS build (system crypto policy, no post-quantum TLS)";
#else
  s += ", post-quantum TLS (ML-KEM, ML-DSA)";
#endif
  if(fips_mode()) s += ", FIPS mode on";
  return s;
}

// Key exchange groups and signature algorithms for one context. Empty
// settings use the DRLB defaults, except in FIPS mode where the crypto
// policy lists are kept. "system" keeps the crypto policy lists. The
// FIPS build always keeps the crypto policy lists.
static int set_groups_sigalgs(SSL_CTX *ctx)
{
  const SSLConfig &ssl = cfg.ssl;
#if defined(DRLB_FIPS_BUILD)
  (void)ctx;
  (void)ssl;
  return 0;
#else
  bool fips = fips_mode();
  std::string groups = ssl.ssl_groups, sigalgs = ssl.ssl_sigalgs;
  if(groups.empty()) groups = fips ? "system" : DefaultGroups;
  if(sigalgs.empty()) sigalgs = fips ? "system" : DefaultSigalgs;
  if(to_upper(groups) != "SYSTEM" && SSL_CTX_set1_groups_list(ctx, groups.c_str()) != 1) {
    nt_print("ERROR - Bad ssl_groups:", groups.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  if(to_upper(sigalgs) != "SYSTEM" && SSL_CTX_set1_sigalgs_list(ctx, sigalgs.c_str()) != 1) {
    nt_print("ERROR - Bad ssl_sigalgs:", sigalgs.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  return 0;
#endif
}

static int set_protocol(SSL_CTX *ctx, int min_version, int max_version)
{
  if(SSL_CTX_set_min_proto_version(ctx, min_version) != 1) return 1;
  if(max_version && SSL_CTX_set_max_proto_version(ctx, max_version) != 1) return 1;
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  return 0;
}

static int load_dh_parms(SSL_CTX *ctx, const char *fname)
{
  BIO *bio = BIO_new_file(fname, "r");
  if(!bio) return 1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY *dh = PEM_read_bio_Parameters(bio, nullptr);
  BIO_free(bio);
  if(!dh) return 1;
  if(SSL_CTX_set0_tmp_dh_pkey(ctx, dh) != 1) { // ctx owns dh on success
    EVP_PKEY_free(dh);
    return 1;
  }
#else
  DH *dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if(!dh) return 1;
  int rv = SSL_CTX_set_tmp_dh(ctx, dh);
  DH_free(dh);
  if(rv != 1) return 1;
#endif
  return 0;
}

int tls_init()
{
  SSLConfig &ssl = cfg.ssl;
  namespace fs = std::filesystem;

  if(!fs::exists(ssl.ssl_key_file)) {
    nt_print("ERROR - Missing private key:", ssl.ssl_key_file.c_str());
    return 1;
  }
  if(!fs::exists(ssl.ssl_cert_file)) {
    nt_print("ERROR - Missing SSL cert:", ssl.ssl_cert_file.c_str());
    return 1;
  }
  if(ssl.ssl_use_dhparms && !fs::exists(ssl.ssl_dhparms_file)) {
    nt_print("ERROR - Missing dhparms file:", ssl.ssl_dhparms_file.c_str());
    return 1;
  }

  nt_print(openssl_build_info());
  if(check_openssl_version() != 0) return 1;

  // Only TLS 1.2 and TLS 1.3
  int min_version = 0, max_version = 0;
  std::string proto = to_upper(ssl.ssl_protocol);
  if(proto == "TLS") {
    min_version = TLS1_2_VERSION;
    nt_print("SSL connections will use TLS 1.2 or TLS 1.3");
  }
  else if(proto == "TLSV1_2") {
    min_version = max_version = TLS1_2_VERSION;
    nt_print("SSL connections will only use TLS 1.2");
    if(pqc_build()) nt_print("WARNING - TLS 1.2 has no post-quantum key exchange, use ssl_protocol = TLS or TLSv1_3");
  }
  else if(proto == "TLSV1_3") {
    min_version = max_version = TLS1_3_VERSION;
    nt_print("SSL connections will only use TLS 1.3");
  }
  else {
    nt_print("ERROR - Unsupported ssl_protocol:", ssl.ssl_protocol.c_str());
    nt_print("ERROR - Use TLS, TLSv1_2 or TLSv1_3");
    return 1;
  }

  // Frontend server context
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if(!ctx || set_protocol(ctx, min_version, max_version) != 0) {
    nt_print("ERROR - Cannot initialize the SSL server context");
    if(ctx) SSL_CTX_free(ctx);
    return 1;
  }
  ssl.server_ctx = ctx;
  nt_print("Loading SSL key and cert");
  if(SSL_CTX_use_certificate_chain_file(ctx, ssl.ssl_cert_file.c_str()) != 1) {
    nt_print("ERROR - Problem loading key and cert");
    nt_print("ERROR - Cannot load certificate:", ssl.ssl_cert_file.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, ssl.ssl_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
    nt_print("ERROR - Problem loading key and cert");
    nt_print("ERROR - Cannot load private key:", ssl.ssl_key_file.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  if(SSL_CTX_check_private_key(ctx) != 1) {
    nt_print("ERROR - Private key does not match the certificate:", ssl.ssl_key_file.c_str());
    return 1;
  }
  if(EVP_PKEY *pk = SSL_CTX_get0_privatekey(ctx)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const char *type = EVP_PKEY_get0_type_name(pk);
#else
    const char *type = OBJ_nid2sn(EVP_PKEY_base_id(pk));
#endif
    nt_print("Certificate key type:", type ? type : "unknown");
  }
  if(fips_mode() && std::string(DRLB_OPENSSL_FLAVOR) == "static") {
    nt_print("WARNING - FIPS mode is on, but this program's built-in OpenSSL is not FIPS validated");
    nt_print("WARNING - On a FIPS mode host use the drlb_server package (FIPS build on the system OpenSSL)");
  }
  if(!pqc_build()) {
    nt_print("INFO - FIPS build: post-quantum TLS (ML-KEM key exchange, ML-DSA certificates) is not available");
    nt_print("INFO - TLS key exchange groups and signature algorithms follow the system crypto policy");
    if((!ssl.ssl_groups.empty() && to_upper(ssl.ssl_groups) != "SYSTEM") ||
       (!ssl.ssl_sigalgs.empty() && to_upper(ssl.ssl_sigalgs) != "SYSTEM")) {
      nt_print("WARNING - ssl_groups and ssl_sigalgs are ignored in the FIPS build");
    }
  }
  else {
    std::string g = ssl.ssl_groups.empty() ? "default (hybrid ML-KEM first)" : ssl.ssl_groups;
    if(ssl.ssl_groups.empty() && fips_mode()) g = "system (FIPS mode)";
    nt_print("TLS key exchange groups:", g.c_str());
  }
  if(!ssl.ssh_ca_list_file.empty() &&
     SSL_CTX_load_verify_locations(ctx, ssl.ssh_ca_list_file.c_str(), nullptr) != 1) {
    nt_print("ERROR - Cannot load the certificate chain:", ssl.ssh_ca_list_file.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  if(set_ssl_ciphers(ctx) != 0) return 1;
  if(set_groups_sigalgs(ctx) != 0) return 1;
  if(ssl.ssl_use_dhparms) {
    nt_print("Loading Diffie-Hellman parameters");
    if(load_dh_parms(ctx, ssl.ssl_dhparms_file.c_str()) != 0) {
      nt_print("ERROR - Problem loading DH parms", ssl.ssl_dhparms_file.c_str());
      nt_print(ssl_error_string());
      return 1;
    }
  }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  else {
    SSL_CTX_set_dh_auto(ctx, 1); // Built in RFC 7919 groups for DHE suites
  }
#endif

  // Backend client context, shared by all backend connections
  if(ssl.ssl_encrypt_backend) {
    SSL_CTX *b = SSL_CTX_new(TLS_client_method());
    if(!b || set_protocol(b, min_version, max_version) != 0) {
      nt_print("ERROR - Cannot initialize the backend SSL context");
      if(b) SSL_CTX_free(b);
      return 1;
    }
    ssl.client_ctx = b;
    if(ssl.ssl_verify_backend_cert) {
      if(!ssl.ssl_backend_ca_list_file.empty()) {
        if(SSL_CTX_load_verify_locations(b, ssl.ssl_backend_ca_list_file.c_str(), nullptr) != 1) {
          nt_print("ERROR - Cannot initialize the backend SSL context");
          nt_print("ERROR - Check ssl_backend_ca_list_file:", ssl.ssl_backend_ca_list_file.c_str());
          return 1;
        }
      }
      else {
        SSL_CTX_set_default_verify_paths(b); // OpenSSL default trust store
        // The static OpenSSL's default paths are under its own prefix,
        // so also load the RHEL system trust store
        if(std::filesystem::exists("/etc/pki/tls/certs/ca-bundle.crt"))
          SSL_CTX_load_verify_locations(b, "/etc/pki/tls/certs/ca-bundle.crt", nullptr);
      }
      nt_print("Backend certificates will be verified");
    }
    else {
      nt_print("WARNING - Backend certificates will not be verified");
    }
    if(set_ssl_ciphers(b) != 0) return 1;
    if(set_groups_sigalgs(b) != 0) return 1;
    nt_print("Backend connections will use SSL/TLS");
  }
  return 0;
}

void tls_cleanup()
{
  if(cfg.ssl.server_ctx) SSL_CTX_free(cfg.ssl.server_ctx);
  if(cfg.ssl.client_ctx) SSL_CTX_free(cfg.ssl.client_ctx);
  cfg.ssl.server_ctx = cfg.ssl.client_ctx = nullptr;
}

// Frontend TLS handshake. The socket timeouts bound the handshake so a
// client that never finishes it cannot hold the thread. Returns 0 if
// the handshake completed.
int tls_accept(ClientSocket *s)
{
  set_socket_timeouts(s->client_socket, cfg.ssl.ssl_handshake_timeout_secs, cfg.ssl.ssl_handshake_timeout_secs);
  ERR_clear_error();
  s->frontend_ssl = SSL_new(cfg.ssl.server_ctx);
  if(!s->frontend_ssl || SSL_set_fd(s->frontend_ssl, s->client_socket) != 1) {
    if(cfg.log_level >= 3) {
      log_message("[" + std::to_string(s->seq_num) + "]: Error opening frontend SSL socket");
      log_message("[" + std::to_string(s->seq_num) + "]: " + ssl_error_string());
    }
    return 1;
  }
  if(SSL_accept(s->frontend_ssl) != 1) {
    if(cfg.log_level >= 3) {
      log_message("[" + std::to_string(s->seq_num) + "]: Error accepting frontend SSL socket");
      std::string err = ssl_error_string();
      if(!err.empty()) log_message("[" + std::to_string(s->seq_num) + "]: SSL global exception: " + err);
    }
    return 1;
  }
  if(cfg.log_level >= 4) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    const char *g = SSL_get0_group_name(s->frontend_ssl);
#else
    const char *g = "n/a";
#endif
    log_message("[" + std::to_string(s->seq_num) + "]: Frontend " + SSL_get_version(s->frontend_ssl) +
                " " + SSL_get_cipher_name(s->frontend_ssl) + " group " + (g ? g : "none"));
  }
  return 0;
}

// Backend TLS handshake on the connected backend socket. The name sent
// as SNI and checked against the certificate is ssl_backend_hostname if
// set, or the node host name or IP. Returns 0 if the handshake
// completed.
int tls_connect(ClientSocket *s, const Node *n)
{
  const SSLConfig &ssl = cfg.ssl;
  std::string seq = "[" + std::to_string(s->seq_num) + "]: ";
  set_socket_timeouts(s->backend_socket, ssl.ssl_handshake_timeout_secs, ssl.ssl_handshake_timeout_secs);
  ERR_clear_error();
  s->backend_ssl = SSL_new(ssl.client_ctx);
  if(!s->backend_ssl || SSL_set_fd(s->backend_ssl, s->backend_socket) != 1) {
    if(cfg.log_level >= 3) {
      log_message(seq + "Error opening backend SSL socket");
      log_message(seq + ssl_error_string());
    }
    return 1;
  }
  const std::string &host = ssl.ssl_backend_hostname.empty() ? n->hostname : ssl.ssl_backend_hostname;
  unsigned char addr[16];
  bool is_ip = inet_pton(AF_INET, host.c_str(), addr) == 1 || inet_pton(AF_INET6, host.c_str(), addr) == 1;
  if(!is_ip) SSL_set_tlsext_host_name(s->backend_ssl, host.c_str()); // SNI is only sent for DNS names
  if(ssl.ssl_verify_backend_cert) {
    X509_VERIFY_PARAM *param = SSL_get0_param(s->backend_ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if(is_ip) X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str());
    else SSL_set1_host(s->backend_ssl, host.c_str());
    SSL_set_verify(s->backend_ssl, SSL_VERIFY_PEER, nullptr);
  }
  else {
    SSL_set_verify(s->backend_ssl, SSL_VERIFY_NONE, nullptr);
  }
  if(SSL_connect(s->backend_ssl) != 1) {
    log_message(seq + "Error connecting to backend SSL socket, certificate check: " +
                X509_verify_cert_error_string(SSL_get_verify_result(s->backend_ssl)));
    std::string err = ssl_error_string();
    if(!err.empty()) log_message(seq + err);
    return 1;
  }
  if(cfg.log_level >= 4) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    const char *g = SSL_get0_group_name(s->backend_ssl);
#else
    const char *g = "n/a";
#endif
    log_message(seq + "Backend " + SSL_get_version(s->backend_ssl) + " " +
                SSL_get_cipher_name(s->backend_ssl) + " group " + (g ? g : "none"));
  }
  return 0;
}

// Send TLS close_notify on both sides. Without it OpenSSL 3 clients
// report "unexpected eof while reading" and treat the response as
// truncated.
void tls_shutdown(ClientSocket *s)
{
  if(s->frontend_ssl) SSL_shutdown(s->frontend_ssl);
  if(s->backend_ssl) SSL_shutdown(s->backend_ssl);
}

void close_backend(ClientSocket *s)
{
  if(s->backend_ssl) {
    SSL_free(s->backend_ssl);
    s->backend_ssl = nullptr;
  }
  if(s->backend_socket >= 0) {
    close(s->backend_socket);
    s->backend_socket = -1;
  }
}

ClientSocket::~ClientSocket()
{
  if(frontend_ssl) SSL_free(frontend_ssl);
  if(client_socket >= 0) close(client_socket);
  close_backend(this);
}

} // namespace drlb
