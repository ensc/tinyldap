#include "tinytls.h"
#include <stdlib.h>
#include <libowfat/uint16.h>
#include <libowfat/uint32.h>
#include <libowfat/buffer.h>
#include <string.h>

inline int puts(const char* s) {
  buffer_putmflush(buffer_1,s,"\n");
  return 0;
}

tls_error_code tls_connect(uintptr_t fd,struct ssl_context* sc) {
  size_t l;
  tls_error_code r,ret=PROTOCOLFAIL;
  switch (sc->state) {
  case NONE:
    puts("TLS_CONNECT");
    // initial connect attempt; send client hello
    sc->message.l=fmt_tls_clienthello(NULL,sc);
    // scratch should be enough to hold the client hello
    // depending on session data length and sc->hostname
    if (sc->message.l<=sizeof(sc->scratch))
      sc->message.s=sc->scratch;
    else {
      if (!(sc->message.s=malloc(sc->message.l)))
	return OOM;
    }
    sc->message.l=fmt_tls_clienthello((char*)sc->message.s,sc);
    sc->ofsinmessage=0; sc->message.s=sc->scratch;
    sc->state=WRITE_CLIENTHELLO;
    // fall through

  case WRITE_CLIENTHELLO:
    puts("WRITE_CLIENTHELLO");
    r=tls_dowrite(fd,sc);
    if (r!=OK) return r;
    // r=READ_SERVERHELLO;	// since we fall through, don't do dead store
    sc->ofsinmessage=0;
    // fall through

  case READ_SERVERHELLO:
    puts("READ_SERVERHELLO");
    r=tls_doread(fd,sc);
    if (r!=OK) return r;
    if (sc->message.s[0]!=22) {		// "handshake"
nothandshake:
      fmt_tls_alert_pkt(sc->scratch,2,UNEXPECTED_MESSAGE);
      goto alertfail;
    }
    if ((l=uint16_read_big(sc->message.s+3))<54) {	// outer length
decodeerror:
      fmt_tls_alert_pkt(sc->scratch,2,DECODE_ERROR);
      goto alertfail;
    }
    if (sc->message.s[5]!=2) goto nothandshake;	// "server hello"
    if ((uint32_read_big(sc->message.s+5)&0xffffff)+4!=l) goto decodeerror;	// inner length
    if ((size_t)(unsigned char)(sc->message.s[5+38])+54<l) goto decodeerror;
    {
      const char* x=sc->message.s+sc->message.s[5+38]+5+38+1;
      // make sure they don't pull a fast one on us
      // and "agree" to a cipher/compression method we did not offer
      uint16_t cipher=uint16_read_big(x);
      if (tls_cipherprio(cipher)<0) goto decodeerror;
      if (x[2]!=0) goto decodeerror;
      sc->cipher=cipher;
      sc->compressionmethod=0;
    }
    // r=READ_CERT;		// since we fall through, this would be a dead store
    sc->ofsinmessage=0;
    // fall through

  case READ_CERT:
    puts("READ_CERT");
    r=tls_doread(fd,sc);
    if (r!=OK) return r;
    if (sc->message.s[0]!=22) goto nothandshake;	// "handshake"
    if ((l=uint16_read_big(sc->message.s+3))<50) goto decodeerror;
    if (sc->message.s[5]!=11) goto nothandshake;	// "certificate"
    if ((uint32_read_big(sc->message.s+5)&0xffffff)+4!=l) goto decodeerror;	// inner length
    if ((uint32_read_big(sc->message.s+8)&0xffffff)+7!=l) goto decodeerror;	// innerer length
    {
      const char* x=sc->message.s+9+3;
      const char* max=x+l-7;
      size_t i;
      sc->theircert[0].s=malloc(l);
      for (i=0; i<MAXCERT; ++i) {
	if (x>=max) break;
	if (x[0]) goto decodeerror;
	sc->theircert[i].l=uint16_read_big(x+1);
	x+=3;
	if ((uintptr_t)(max-x) < sc->theircert[i].l) goto decodeerror;
	if (i!=0) sc->theircert[i].s=sc->theircert[i-1].s+sc->theircert[i-1].l;
	memcpy((char*)sc->theircert[i].s,x,sc->theircert[i].l);
	x+=sc->theircert[i].l;
      }
    }

    // r=READ_SERVERHELLODONE;	// since we fall through, this would be a dead store
    sc->ofsinmessage=0;
    // fall through

case READ_SERVERHELLODONE:
    puts("READ_SERVERHELLODONE");
    r=tls_doread(fd,sc);
    if (r!=OK) return r;
    if (sc->message.s[0]!=22) goto nothandshake;	// "handshake"
    if ((l=uint16_read_big(sc->message.s+3))!=4) goto decodeerror;
    if (sc->message.s[5]!=14) goto nothandshake;	// "server hello done"
    if ((uint32_read_big(sc->message.s+5)&0xffffff)+4!=l) goto decodeerror;	// inner length
    return OK;

  case WRITE_ALERTFAIL:
alertfail:
    sc->state=WRITE_ALERTFAIL;
    sc->message.s=sc->scratch;
    sc->message.l=7;
    r=tls_dowrite(fd,sc);
    if (r!=OK) return r;
    /* fall through */

  default:
    sc->state=FAIL;
  }
  return ret;
}
