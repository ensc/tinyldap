#include "tinytls.h"
#include <libowfat/uint16.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

tls_error_code tls_doread(uintptr_t fd,struct ssl_context* sc) {
  size_t l;
  ssize_t r;
again:
  if (sc->ofsinmessage < 5) {
    // we have not read anything yet.
    // point message to scratch and read the first bit
    sc->message.s=sc->scratch;
    sc->message.l=0;
    l=5-sc->ofsinmessage;
  } else {
    // we have read enough to know how much we are supposed to be reading
    // in this case s->message is setup right for us already
    l=sc->message.l-sc->ofsinmessage;
  }

  if (sc->_read)
    r=sc->_read(fd,(char*)sc->message.s+sc->ofsinmessage,l);
  else
    r=read(fd,(char*)sc->message.s+sc->ofsinmessage,l);

  if (r==0)	// EOF when we expected something -> protocol error
    return PROTOCOLFAIL;

  if (r<0) {
    // we accept the traditional -1+errno
    // and the libowfat -3+errno for error and -1 for EAGAIN
    // as long as errno is still set to EAGAIN
    if (r==-3) return IOFAIL;
    if (r==-1)
      return errno==EAGAIN ? WANTREAD : IOFAIL;
    return YOUSUCK;
  }

  if ((size_t)r>l)
    return YOUSUCK;	// callback says it read more than we asked for

  sc->ofsinmessage+=l;
  if (sc->ofsinmessage>=5 && sc->ofsinmessage-l<5) {
    // we did not know how much we wanted before, but we do now
    sc->message.l=5+uint16_read_big(sc->scratch+3);
    if (sc->message.l>sizeof(sc->scratch)) {
      char* x;
      if (!(x=realloc((char*)sc->message.s,sc->message.l)))
	return OOM;
      sc->message.s=(char*)x;	// make sure we don't clobber sc->message.s in the OOM case
      memcpy((char*)sc->message.s,sc->scratch,sc->ofsinmessage-l);
    }
    /* attempt to read the rest */
    goto again;
  }
  
  if (sc->ofsinmessage >= sc->message.l) {
    // we read one full packet. See if it is an alert.
    if (sc->message.s[0]==ALERT) {
      if (sc->message.l!=7)	// alerts are 5 bytes header plus 2 bytes alert
	return PROTOCOLFAIL;
      // it is an alert; skip warnings, signal errors
      if (sc->message.s[5]==1) {
	// it's a warning, we can ignore it.
	if (sc->ofsinmessage>7) {
	  // since we initially read into scratch, we could have read
	  // more than 7 bytes. Move latter part forward.
	  memmove((char*)sc->message.s+7,sc->message.s,sc->ofsinmessage-7);
	  sc->ofsinmessage-=7;
	  goto again;
	}
      }

      switch (sc->message.s[6]) {
      case BAD_RECORD_MAC:
      case DECRYPTION_FAILED:
      case DECRYPT_ERROR:
      case EXPORT_RESTRICTION:
      case INSUFFICIENT_SECURITY:
	return CRYPTOFAIL;

      case HANDSHAKE_FAILURE:
      case INTERNAL_ERROR:
      case USER_CANCELED:
      case NO_RENEGOTIATION:
	return NEGOTIATIONFAIL;

      case NO_CERT:
      case BAD_CERT:
      case UNSUPPORTED_CERT:
      case CERT_REVOKED:
      case CERT_EXPIRED:
      case CERT_UNKNOWN:
      case UNKNOWN_CA:
	return CERTFAIL;

      default:
	return PROTOCOLFAIL;
      }
    }
    return OK;
  }
  return WANTREAD;
}

void tls_prepare_next_read(struct ssl_context* sc) {
  size_t psize;
  if (sc->message.s==sc->scratch &&	// we are reading into scratch
      sc->message.l>5 &&		// we have a header
      sc->message.l>(psize=5+uint16_read_big(sc->scratch+3))) {
    // we have a handled packet and extra data in the scratch buffer
    // memmove the rest over the handled packet
    memmove(sc->scratch,sc->scratch+psize,sc->message.l-psize);
    sc->message.l-=psize;
  }
  sc->ofsinmessage=0;
}

