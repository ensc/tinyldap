#include "tinytls.h"
#include <libowfat/open.h>
#include <unistd.h>
#include <string.h>

void init_tls_context_norandom(struct ssl_context* sc, const char* servername) {
  memset(sc,0,sizeof *sc);
  sc->servername=servername;
}

int init_tls_context(struct ssl_context* sc, const char* servername) {
  int fd=open_read("/dev/urandom");
  int r;
  if (fd==-1) return -1;
  init_tls_context_norandom(sc,servername);
  r=read(fd,sc->myrandom,sizeof(sc->myrandom));
  close(fd);
  if (r!=sizeof(sc->myrandom)) return -1;
  return 0;
}
