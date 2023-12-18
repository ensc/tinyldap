#ifndef H_TINYLDAP_IO_H
#define H_TINYLDAP_IO_H

#include <stdlib.h>

struct io_ctx;

struct io_ctx *io_ctx_new(void);

/* only defined for plaintext io types */
struct io_ctx *io_ctx_new_plain(int fd_in, int fd_out);

int io_ctx_accept(struct io_ctx *ctx, int sock_fd);
int io_ctx_read(struct io_ctx *ctx, void *data, size_t len);
int io_ctx_write_all(struct io_ctx *ctx, void const *data, size_t len);
void io_ctx_close(struct io_ctx *ctx);

void io_ctx_destroy_global(void);

#endif	/* H_TINYLDAP_IO_H */
