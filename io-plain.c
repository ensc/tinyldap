#include "io.h"

#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <libowfat/socket.h>
#include <libowfat/buffer.h>

struct io_ctx {
  int fd_in;
  int fd_out;
};

struct io_ctx *io_ctx_new(void)
{
  return io_ctx_new_plain(-1, -1);
}

struct io_ctx *io_ctx_new_plain(int fd_in, int fd_out)
{
  struct io_ctx *res = malloc(sizeof *res);

  if (!res)
    abort();

  *res = (struct io_ctx) {
    .fd_in = fd_in,
    .fd_out = fd_out,
  };

  return res;
}

int io_ctx_accept(struct io_ctx *ctx, int sock_fd) {
  int one=1;
  uint16 port;
  uint32 scope_id;
  char ip[16];
  int asock;

  asock=socket_accept6(sock_fd,ip,&port,&scope_id);
  if (asock==-1) {
    buffer_putsflush(buffer_2,"accept failed!\n");
    return -1;
  }

  setsockopt(asock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  setsockopt(asock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

  ctx->fd_in = asock;
  ctx->fd_out = asock;

  return 0;
}

int io_ctx_handshake(struct io_ctx *_ctx)
{
  (void)_ctx;
  return 0;
}

int io_ctx_read(struct io_ctx *ctx, void *data, size_t len)
{
  int l = read(ctx->fd_in, data, len);

  if (l < 0) {
    buffer_putsflush(buffer_2,"mbedtls_net_recv() failed!\n");
    return -1;
  }

  return l;
}

int io_ctx_write_all(struct io_ctx *ctx, void const *data, size_t len)
{
  while (len > 0) {
    ssize_t	l = write(ctx->fd_out, data, len);

    if (l < 0) {
      buffer_putsflush(buffer_2, "write() failed!\n");
      return -1;
    }

    data += l;
    len -= l;
  }

  return 0;
}

void io_ctx_close(struct io_ctx *ctx)
{
  close(ctx->fd_in);

  if (ctx->fd_in != ctx->fd_out)
    close(ctx->fd_out);
}

void io_ctx_destroy_global(void)
{
}
