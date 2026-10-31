// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// SSL/TLS with OpenSSL: the frontend server context, the backend client
// context, and the per connection handshakes. Same settings and
// defaults as the 1.60 SSL bridge: TLS 1.2 and 1.3 only, ciphers from
// the system crypto policy, backend certificates verified by default.

#include "drlb.h"

#include <filesystem>
#include <sstream>

#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

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

  nt_print("OpenSSL version:", OpenSSL_version(OPENSSL_VERSION));

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
  if(!ssl.ssh_ca_list_file.empty() &&
     SSL_CTX_load_verify_locations(ctx, ssl.ssh_ca_list_file.c_str(), nullptr) != 1) {
    nt_print("ERROR - Cannot load the certificate chain:", ssl.ssh_ca_list_file.c_str());
    nt_print(ssl_error_string());
    return 1;
  }
  if(set_ssl_ciphers(ctx) != 0) return 1;
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
        SSL_CTX_set_default_verify_paths(b); // System trust store
      }
      nt_print("Backend certificates will be verified");
    }
    else {
      nt_print("WARNING - Backend certificates will not be verified");
    }
    if(set_ssl_ciphers(b) != 0) return 1;
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
