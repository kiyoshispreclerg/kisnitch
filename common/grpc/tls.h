/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * TLS for the gRPC connections between daemon and UI ("tls-simple" and
 * "tls-mutual"), with OpenSSL when built with TLS=1.
 *
 * The client (daemon) follows upstream's daemon/ui/auth/auth.go: the
 * trusted roots are the CA certificate and the server certificate, if
 * given (no system roots); SkipVerify skips the verification; with
 * "tls-mutual" a client certificate and key are presented. Like Go, the
 * server name is checked against the certificate's subject alternative
 * names only (an IP address against its IP SANs), and a certificate in the
 * roots is trusted even if it isn't self-signed.
 *
 * The server (UI) follows grpc.ssl_server_credentials() as upstream's
 * ui/opensnitch/auth uses it: a certificate and key; with a CA
 * certificate, clients must present a certificate it verifies.
 *
 * Both sides negotiate ALPN "h2", as gRPC does.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a context is owned by its creator; connections hold their own
 * reference, so it may be freed while they live.
 */
#ifndef KS_COMMON_GRPC_TLS_H
#define KS_COMMON_GRPC_TLS_H

#include <stdbool.h>
#include <stddef.h>

struct ks_tls_ctx;

/* Whether this build has TLS (TLS=1). */
bool ks_tls_available(void);

struct ks_tls_client_opts {
    const char *ca_cert;     /* CACert: PEM file, "" or NULL for none */
    const char *server_cert; /* ServerCert */
    const char *client_cert; /* ClientCert (mutual) */
    const char *client_key;  /* ClientKey (mutual) */
    bool skip_verify;        /* SkipVerify */
    bool mutual;             /* "tls-mutual" */
};

/* auth.New(). Unreadable root files are warnings, as upstream; a bad
 * client certificate or key is an error. NULL with `err` filled. */
struct ks_tls_ctx *ks_tls_client_new(const struct ks_tls_client_opts *o, char *err,
                                     size_t errlen);
/* get_tls_credentials(ca, cert, key) */
struct ks_tls_ctx *ks_tls_server_new(const char *cert, const char *key, const char *ca,
                                     char *err, size_t errlen);
void ks_tls_ctx_free(struct ks_tls_ctx *ctx);

/* ---- for common/grpc/grpc.c ------------------------------------------- */

/* A TLS session over `fd`. `host` (client only) is the name to verify:
 * an IP address or a DNS name. NULL on OOM. */
void *ks_tls_session_new(struct ks_tls_ctx *ctx, int fd, const char *host);
void ks_tls_session_free(void *s);

enum { KS_TLS_OK = 1, KS_TLS_WANT_READ = -1, KS_TLS_WANT_WRITE = -2, KS_TLS_EOF = 0,
       KS_TLS_ERROR = -3 };

/* The handshake: KS_TLS_OK when done, KS_TLS_WANT_*, or KS_TLS_ERROR with
 * the reason in `err` (a failed verification names its cause). */
int ks_tls_handshake(void *s, char *err, size_t errlen);
/* Bytes read or written (> 0), KS_TLS_EOF, KS_TLS_WANT_*, KS_TLS_ERROR. */
long ks_tls_read(void *s, void *buf, size_t len, char *err, size_t errlen);
long ks_tls_write(void *s, const void *buf, size_t len, char *err, size_t errlen);
/* Decrypted bytes waiting (read them before waiting on the fd again). */
bool ks_tls_pending(void *s);

#endif
