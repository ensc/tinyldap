#include "io.h"

#include <sys/random.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

#include <libowfat/buffer.h>

struct io_ctx {
  struct mbedtls_ssl_context tls;
  struct mbedtls_net_context net;
  /* hack; the io_ctx_close() in the fork() parent should simply close the
     connection.  Use this flag to mark this state */
  int have_handshake;
};

struct tls_config {
  struct mbedtls_ssl_config	tls;
  struct mbedtls_x509_crt	crt;
  struct mbedtls_pk_context	pk;
};

static struct tls_config g_tls_config;
static struct mbedtls_entropy_context g_tls_entropy;
static struct mbedtls_ctr_drbg_context g_tls_drbg;

static void tls_print_error(int rc, char const *ctx)
{
  char buf[256];

  mbedtls_strerror(rc, buf, sizeof buf);

  buffer_puts(buffer_2, ctx);
  buffer_puts(buffer_2, ": ");
  buffer_puts(buffer_2, buf);
  buffer_putsflush(buffer_2, "\n");
}

static int tls_read_certs(struct tls_config *cfg)
{
  char const *tls_key = getenv("TINYLDAP_TLS_KEY");
  char const *tls_crt = getenv("TINYLDAP_TLS_CRT");
  char const *tls_chain = getenv("TINYLDAP_TLS_CHAIN");

  int rc;

  if (!tls_crt || !tls_key) {
    buffer_putsflush(buffer_2, "missing TINYLDAP_TLS_KEY/CRT");
    return -1;
  }

  mbedtls_x509_crt_init(&cfg->crt);
  mbedtls_pk_init(&cfg->pk);

  rc = mbedtls_x509_crt_parse_file(&cfg->crt, tls_crt);
  if (rc < 0) {
    tls_print_error(rc, "failed to parse TINYLDAP_TLS_CRT");
    goto out;
  }

  if (tls_chain) {
    rc = mbedtls_x509_crt_parse_file(&cfg->crt, tls_chain);
    if (rc < 0) {
      tls_print_error(rc, "failed to parse TINYLDAP_TLS_CHAIN");
      goto out;
    }
  }

  rc = mbedtls_pk_parse_keyfile(&cfg->pk, tls_key, NULL);
  if (rc < 0) {
    tls_print_error(rc, "failed to parse TINYLDAP_TLS_KEY");
    goto out;
  }

  rc = mbedtls_ssl_conf_own_cert(&cfg->tls, &cfg->crt, &cfg->pk);
  if (rc < 0) {
    tls_print_error(rc, "mbedtls_ssl_conf_own_cert() failed: \n");
    goto out;
  }

  rc = 0;

out:
  /* TODO: cleanup certs + keys in error case */
  return rc;
}

static void tls_print_debug(void *_, int lvl, char const *fname, int line, char const *msg)
{
  (void)_;
  (void)lvl;

  fprintf(stderr, "%s:%u %s", fname, line, msg);
}

static void tls_seed_rng(struct mbedtls_ctr_drbg_context *drbg)
{
  unsigned char buf[64];
  ssize_t l;

  l = getrandom(buf, sizeof buf, GRND_NONBLOCK);

  if (l > 0)
    mbedtls_ctr_drbg_reseed(drbg, buf, l);
}

static int tls_init_globals(void)
{
  int rc;

  /* TODO: is this really ok?  We do ssl ops after 'fork()' so that parent
     state does not change.  There is a manual tls_seed_rng() but is this
     enough? */
  mbedtls_entropy_init(&g_tls_entropy);
  mbedtls_ctr_drbg_init(&g_tls_drbg);

  mbedtls_ssl_config_init(&g_tls_config.tls);

  rc = mbedtls_ssl_config_defaults(&g_tls_config.tls,
                                   MBEDTLS_SSL_IS_SERVER,
				   MBEDTLS_SSL_TRANSPORT_STREAM,
				   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc < 0) {
    tls_print_error(rc, "mbedtls_ssl_config_defaults() failed");
    return -1;
  }

  mbedtls_ctr_drbg_seed(&g_tls_drbg, mbedtls_entropy_func, &g_tls_entropy,
			(void const *)"1f3ca3aa-59de-49b8-b64d-3bdf714a0532", 36);

  mbedtls_ssl_conf_rng(&g_tls_config.tls, mbedtls_ctr_drbg_random, &g_tls_drbg);

  if (0) {
    mbedtls_ssl_conf_dbg(&g_tls_config.tls, tls_print_debug, NULL);
    mbedtls_debug_set_threshold(5);
  }

  rc = tls_read_certs(&g_tls_config);
  if (rc < 0)
    return -1;

  return 0;
}

static int io_ctx_init(struct io_ctx *ctx)
{
  static int is_init = 0;
  int rc;

  if (!is_init) {
    rc = tls_init_globals();
    if (rc < 0)
      return rc;

    is_init = 1;
  }

  ctx->have_handshake = 0;
  mbedtls_net_init(&ctx->net);
  mbedtls_ssl_init(&ctx->tls);
  mbedtls_ssl_set_hostname(&ctx->tls, "localhost");
  mbedtls_ssl_set_bio(&ctx->tls, &ctx->net,
		      mbedtls_net_send,
		      mbedtls_net_recv,
		      mbedtls_net_recv_timeout);

  rc = mbedtls_ssl_setup(&ctx->tls, &g_tls_config.tls);
  if (rc < 0) {
    tls_print_error(rc, "mbedtls_ssl_setup() failed");
    return -1;
  }

  return 0;
}

struct io_ctx *io_ctx_new(void)
{
  struct io_ctx *ctx = malloc(sizeof *ctx);
  int rc;

  if (!ctx)
    abort();

  rc = io_ctx_init(ctx);
  if (rc < 0)
    /* when this fails once, it will fail everytime... */
    abort();

  return ctx;
}

int io_ctx_accept(struct io_ctx *ctx, int sock_fd) {
  mbedtls_net_context bind_ctx = {
    .fd = sock_fd
  };
  int rc;

  rc = mbedtls_net_accept(&bind_ctx, &ctx->net, NULL, 0, NULL);
  if (rc != 0) {
    tls_print_error(rc, "mbedtls_net_accept() failed");
    return -1;
  }

  tls_seed_rng(&g_tls_drbg);

  return 0;
}

int io_ctx_handshake(struct io_ctx *ctx)
{
  int rc;

  ctx->have_handshake = 1;

again:
  rc = mbedtls_ssl_handshake(&ctx->tls);

  switch (rc) {
  case 0:
    break;

  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
  case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
  case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
    goto again;

  default:
    tls_print_error(rc, "mbedtls_ssl_handshake() failed");
    return -1;
  }

  return 0;
}

int io_ctx_read(struct io_ctx *ctx, void *data, size_t len)
{
  int l;

again:
  l = mbedtls_ssl_read(&ctx->tls, data, len);

  switch (l) {
  case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    return 0;

  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
  case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
  case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
    goto again;

  case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
    /* TODO: signal to caller which has to do an implicit UnbindRequest */
    return 0;

  default:
    if (l < 0) {
      tls_print_error(l, "mbedtls_ssl_read() failed");
      return -1;
    }
  }

  return l;
}

int io_ctx_write_all(struct io_ctx *ctx, void const *data, size_t len)
{
  while (len > 0) {
    int	l = mbedtls_ssl_write(&ctx->tls, data, len);

    switch (l) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
    case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
    case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      continue;

    default:
      if (l < 0) {
	tls_print_error(l, "mbedtls_net_send() failed");
	return -1;
      }
    }

    data += l;
    len -= l;
  }

  return 0;
}

void io_ctx_close(struct io_ctx *ctx)
{
  mbedtls_ssl_free(&ctx->tls);

  if (ctx->have_handshake)
    mbedtls_net_free(&ctx->net);
  else
    mbedtls_net_close(&ctx->net);

  free(ctx);
}

void io_ctx_destroy_global(void)
{
  mbedtls_ssl_config_free(&g_tls_config.tls);
  mbedtls_x509_crt_free(&g_tls_config.crt);
  mbedtls_pk_free(&g_tls_config.pk);

  mbedtls_ctr_drbg_free(&g_tls_drbg);
  mbedtls_entropy_free(&g_tls_entropy);
}
