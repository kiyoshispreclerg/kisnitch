/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/ui/auth/auth.go and ui/opensnitch/auth, on
 * OpenSSL. See tls.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/grpc/tls.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

#include "common/log.h"

#ifdef KS_HAVE_TLS
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

struct ks_tls_ctx {
    SSL_CTX *ctx;
    bool server;
};

static const unsigned char alpn_h2[] = {2, 'h', '2'};

bool ks_tls_available(void)
{
    return true;
}

static void ssl_error(char *err, size_t errlen, const char *what)
{
    unsigned long e = ERR_get_error();
    char buf[256] = "";
    if (e != 0)
        ERR_error_string_n(e, buf, sizeof(buf));
    snprintf(err, errlen, "%s%s%s", what, buf[0] ? ": " : "", buf);
    ERR_clear_error();
}

static bool empty(const char *s)
{
    return s == NULL || s[0] == '\0';
}

/* certPool.AppendCertsFromPEM(file): every certificate of the file */
static void append_pem(X509_STORE *store, const char *path, const char *what)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ks_warning("reading UI auth %s (%s): open %s: %s", what, path, path, strerror(errno));
        return;
    }
    int n = 0;
    X509 *x;
    while ((x = PEM_read_X509(f, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_cert(store, x) == 1)
            n++;
        X509_free(x);
    }
    ERR_clear_error();
    fclose(f);
    if (n == 0)
        ks_warning("adding UI auth %s (%s): no certificates found", what, path);
}

static SSL_CTX *new_ctx(bool server, char *err, size_t errlen)
{
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (ctx == NULL) {
        ssl_error(err, errlen, "SSL_CTX_new");
        return NULL;
    }
    /* TLS 1.2 or newer, as Go's and gRPC's defaults */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /* nghttp2 retries a blocked write with the same data, from the same
     * place or not */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;
}

static int load_pair(SSL_CTX *ctx, const char *cert, const char *key, char *err, size_t errlen)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
        ssl_error(err, errlen, "loading the certificate");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == X509_R_KEY_VALUES_MISMATCH) {
            ERR_clear_error();
            snprintf(err, errlen, "tls: private key does not match public key");
        } else {
            ssl_error(err, errlen, "loading the key");
        }
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        ssl_error(err, errlen, "tls: private key does not match public key");
        return -1;
    }
    return 0;
}

struct ks_tls_ctx *ks_tls_client_new(const struct ks_tls_client_opts *o, char *err,
                                     size_t errlen)
{
    SSL_CTX *ctx = new_ctx(false, err, errlen);
    if (ctx == NULL)
        return NULL;
    /* RootCAs: only the given files (Go doesn't add the system's roots
     * when RootCAs is set) */
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!empty(o->ca_cert))
        append_pem(store, o->ca_cert, "CA certificate");
    if (!empty(o->server_cert))
        append_pem(store, o->server_cert, "server cert");
    /* a certificate of the pool is a trust anchor, self-signed or not */
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    SSL_CTX_set_verify(ctx, o->skip_verify ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
    if (o->mutual && load_pair(ctx, o->client_cert != NULL ? o->client_cert : "",
                               o->client_key != NULL ? o->client_key : "", err, errlen) < 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_alpn_protos(ctx, alpn_h2, sizeof(alpn_h2));
    struct ks_tls_ctx *t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL) {
        SSL_CTX_free(ctx);
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    t->ctx = ctx;
    return t;
}

static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    unsigned char *sel;
    if (SSL_select_next_proto(&sel, outlen, alpn_h2, sizeof(alpn_h2), in, inlen) !=
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

struct ks_tls_ctx *ks_tls_server_new(const char *cert, const char *key, const char *ca,
                                     char *err, size_t errlen)
{
    if (empty(cert) || empty(key)) {
        snprintf(err, errlen, "a certificate and a key are needed");
        return NULL;
    }
    SSL_CTX *ctx = new_ctx(true, err, errlen);
    if (ctx == NULL)
        return NULL;
    if (load_pair(ctx, cert, key, err, errlen) < 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    /* with a CA: require_client_auth */
    if (!empty(ca)) {
        if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
            ssl_error(err, errlen, "loading the CA certificate");
            SSL_CTX_free(ctx);
            return NULL;
        }
        STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(ca);
        if (names != NULL)
            SSL_CTX_set_client_CA_list(ctx, names);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    struct ks_tls_ctx *t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL) {
        SSL_CTX_free(ctx);
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    t->ctx = ctx;
    t->server = true;
    return t;
}

void ks_tls_ctx_free(struct ks_tls_ctx *t)
{
    if (t == NULL)
        return;
    SSL_CTX_free(t->ctx);
    OPENSSL_free(t);
}

/* A socket BIO that never raises SIGPIPE: send() with MSG_NOSIGNAL, as
 * the rest of common/grpc writes (OpenSSL's socket BIO uses write()). */
static int bio_write(BIO *b, const char *data, size_t len, size_t *written)
{
    int fd = (int)(intptr_t)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    for (;;) {
        ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
        if (n >= 0) {
            *written = (size_t)n;
            return 1;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            BIO_set_retry_write(b);
        return 0;
    }
}

static int bio_read(BIO *b, char *buf, size_t len, size_t *readbytes)
{
    int fd = (int)(intptr_t)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    for (;;) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n > 0) {
            *readbytes = (size_t)n;
            return 1;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            BIO_set_retry_read(b);
        else if (n == 0)
            errno = 0; /* EOF */
        return 0;
    }
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

static int bio_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO_METHOD *bio_method(void)
{
    static BIO_METHOD *m;
    if (m == NULL) {
        m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "ks socket");
        if (m != NULL) {
            BIO_meth_set_write_ex(m, bio_write);
            BIO_meth_set_read_ex(m, bio_read);
            BIO_meth_set_ctrl(m, bio_ctrl);
            BIO_meth_set_create(m, bio_create);
        }
    }
    return m;
}

void *ks_tls_session_new(struct ks_tls_ctx *t, int fd, const char *host)
{
    BIO_METHOD *m = bio_method();
    BIO *bio = m != NULL ? BIO_new(m) : NULL;
    SSL *ssl = bio != NULL ? SSL_new(t->ctx) : NULL; /* holds a reference to the context */
    if (ssl == NULL) {
        BIO_free(bio);
        return NULL;
    }
    BIO_set_data(bio, (void *)(intptr_t)fd);
    SSL_set_bio(ssl, bio, bio); /* the SSL owns it */
    if (t->server) {
        SSL_set_accept_state(ssl);
        return ssl;
    }
    SSL_set_connect_state(ssl);
    if (!empty(host)) {
        X509_VERIFY_PARAM *p = SSL_get0_param(ssl);
        /* Go checks the SANs only, never the subject's CN */
        X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        unsigned char ip[16];
        if (inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1) {
            X509_VERIFY_PARAM_set1_ip_asc(p, host);
        } else {
            X509_VERIFY_PARAM_set1_host(p, host, 0);
            SSL_set_tlsext_host_name(ssl, host); /* SNI: names only, as Go */
        }
    }
    return ssl;
}

void ks_tls_session_free(void *s)
{
    if (s == NULL)
        return;
    SSL_shutdown(s); /* best effort: non-blocking */
    SSL_free(s);
    ERR_clear_error();
}

static int status(SSL *ssl, int r, char *err, size_t errlen)
{
    switch (SSL_get_error(ssl, r)) {
    case SSL_ERROR_WANT_READ:
        return KS_TLS_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
        return KS_TLS_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN:
        return KS_TLS_EOF;
    case SSL_ERROR_SYSCALL:
        if (ERR_peek_error() == 0) {
            snprintf(err, errlen, "%s", r == 0 ? "EOF" : "connection reset");
            ERR_clear_error();
            return r == 0 ? KS_TLS_EOF : KS_TLS_ERROR;
        }
        break;
    default:
        break;
    }
    long v = SSL_get_verify_result(ssl);
    if (v != X509_V_OK)
        snprintf(err, errlen, "x509: %s", X509_verify_cert_error_string(v));
    else
        ssl_error(err, errlen, "tls");
    ERR_clear_error();
    return KS_TLS_ERROR;
}

int ks_tls_handshake(void *s, char *err, size_t errlen)
{
    SSL *ssl = s;
    int r = SSL_do_handshake(ssl);
    if (r == 1) {
        const unsigned char *proto;
        unsigned int n;
        SSL_get0_alpn_selected(ssl, &proto, &n);
        /* grpc-go refuses servers that negotiate another protocol */
        if (n > 0 && !(n == 2 && memcmp(proto, "h2", 2) == 0)) {
            snprintf(err, errlen, "credentials: cannot check peer: missing selected ALPN "
                                  "property");
            return KS_TLS_ERROR;
        }
        return KS_TLS_OK;
    }
    return status(ssl, r, err, errlen);
}

long ks_tls_read(void *s, void *buf, size_t len, char *err, size_t errlen)
{
    size_t n = 0;
    int r = SSL_read_ex(s, buf, len, &n);
    return r == 1 ? (long)n : status(s, r, err, errlen);
}

long ks_tls_write(void *s, const void *buf, size_t len, char *err, size_t errlen)
{
    size_t n = 0;
    int r = SSL_write_ex(s, buf, len, &n);
    return r == 1 ? (long)n : status(s, r, err, errlen);
}

bool ks_tls_pending(void *s)
{
    return SSL_pending(s) > 0;
}

#else /* !KS_HAVE_TLS */

bool ks_tls_available(void)
{
    return false;
}

struct ks_tls_ctx *ks_tls_client_new(const struct ks_tls_client_opts *o, char *err,
                                     size_t errlen)
{
    (void)o;
    snprintf(err, errlen, "TLS is not supported by this build (TLS=1)");
    return NULL;
}

struct ks_tls_ctx *ks_tls_server_new(const char *cert, const char *key, const char *ca,
                                     char *err, size_t errlen)
{
    (void)cert;
    (void)key;
    (void)ca;
    snprintf(err, errlen, "TLS is not supported by this build (TLS=1)");
    return NULL;
}

void ks_tls_ctx_free(struct ks_tls_ctx *t)
{
    (void)t;
}

void *ks_tls_session_new(struct ks_tls_ctx *t, int fd, const char *host)
{
    (void)t;
    (void)fd;
    (void)host;
    return NULL;
}

void ks_tls_session_free(void *s)
{
    (void)s;
}

int ks_tls_handshake(void *s, char *err, size_t errlen)
{
    (void)s;
    snprintf(err, errlen, "no TLS");
    return KS_TLS_ERROR;
}

long ks_tls_read(void *s, void *buf, size_t len, char *err, size_t errlen)
{
    (void)s;
    (void)buf;
    (void)len;
    snprintf(err, errlen, "no TLS");
    return KS_TLS_ERROR;
}

long ks_tls_write(void *s, const void *buf, size_t len, char *err, size_t errlen)
{
    (void)s;
    (void)buf;
    (void)len;
    snprintf(err, errlen, "no TLS");
    return KS_TLS_ERROR;
}

bool ks_tls_pending(void *s)
{
    (void)s;
    return false;
}

#endif
