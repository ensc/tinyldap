#include "tinytls.h"
#include <unistd.h>
#include <errno.h>

tls_error_code tls_dowrite(uintptr_t fd,struct ssl_context* sc) {
  size_t l=sc->message.l-sc->ofsinmessage;
  ssize_t r;
  if (sc->_write)
    r=sc->_write(fd,sc->message.s+sc->ofsinmessage,l);
  else
    r=write(fd,sc->message.s+sc->ofsinmessage,l);

  if (r==0)	// EOF when we expected something -> protocol error
    return PROTOCOLFAIL;
  if (r<0) {
    // we accept the traditional -1+errno
    // and the libowfat -3+errno for error and -1 for EAGAIN
    // as long as errno is still set to EAGAIN
    if (r==-3) return IOFAIL;
    if (r==-1)
      return errno==EAGAIN ? WANTWRITE : IOFAIL;
    return YOUSUCK;
  }
  if ((size_t)r>l)
    return YOUSUCK;	// callback says it read more than we asked for

  sc->ofsinmessage+=l;

  return sc->ofsinmessage < sc->message.l ? WANTWRITE : OK;
}
