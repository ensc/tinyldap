#include "tinytls.h"
#include <stdlib.h>
#include <string.h>

tls_error_code tls_accept(uintptr_t fd,struct ssl_context* sc) {
  tls_error_code r,ret=PROTOCOLFAIL;
  size_t l;
  switch (sc->state) {
  case READ_CLIENTHELLO:
    r=tls_doread(fd,sc);
    if (r!=OK) return r;
    
    l=fmt_tls_serverhello(sc->scratch,sc->scratch,sc->ofsinmessage,sc);
    sc->ofsinmessage=0;
    if (l==7)
      // failure, send error message back
      goto alertfail;
    // figure out which certificates to send
    if (sc->readcert) {
      enum alerttype a=sc->readcert(sc);
      if (a!=0) {
	fmt_tls_alert_pkt(sc->scratch,2,a);
	goto alertfail;
      }
    }
    {
      size_t i,s;
      char* x;
      for (i=s=0; i<MAXCERT && sc->mycert[i].l; ++i) {
	if (sc->mycert[i].l>0x1000) {
nocert:
	  fmt_tls_alert_pkt(sc->scratch,2,INTERNAL_ERROR);
	  ret=YOUSUCK;
	  goto alertfail;
	}
	s+=sc->mycert[i].l+3;	// fmt_tls_handshake_cert shortcut
      }
      if (l+s+12+9 > sizeof(sc->scratch)) {
	// l is the size of the serverhello which we generated, at most 309 bytes
	// s is the sum of the sizes of the certificates, at most 0x1003*MAXCERT
	// 12 is for fmt_tls_handshake_certs_header
	// 9 is for fmt_tls_serverhellodone
	//   -> no integer overflow
	char* x=realloc((char*)sc->message.s,l+s+12+9);
	if (!x) {
	  fmt_tls_alert_pkt(sc->scratch,2,INTERNAL_ERROR);
	  ret=OOM;
	  goto alertfail;
	}
	memcpy(x,sc->scratch,l);
	sc->message.s=x;
      }
      sc->message.l=l+s+12+9;
      if (sc->mycert[0].l==0)
	goto nocert;

      x=(char*)sc->message.s+l;
      x+=fmt_tls_handshake_certs_header(x,s);
      for (i=0; i<MAXCERT; ++i)
	if (sc->mycert[i].l)
	  x+=fmt_tls_handshake_cert(x,sc->mycert[i].s,sc->mycert[i].l);
      x+=fmt_tls_serverhellodone(x);
    }

    // r=WRITE_SERVERHELLO;	// dead store because we fall through
    sc->ofsinmessage=0;
    // fall through

  case WRITE_SERVERHELLO:
    r=tls_dowrite(fd,sc);
    if (r!=OK) return r;
    return r;

  case WRITE_ALERTFAIL:
alertfail:
    sc->state=WRITE_ALERTFAIL;
    r=tls_dowrite(fd,sc);
    if (r!=OK) return r;
    // fall through

  default:
    sc->state=FAIL;
  }
  return ret;
}
