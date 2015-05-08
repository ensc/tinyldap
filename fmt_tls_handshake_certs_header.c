#include "tinytls.h"

size_t fmt_tls_handshake_certs_header(char* dest,size_t len_of_certs) {
  if (len_of_certs>0x4000) return 0;	// completely arbitrary decision on my part
  if (dest) {
    /* We need to write two headers containing three lengths */
    /* Someone ought to get their ass kicked for this */
    /* 1. TLS packet layer header */
    dest[0]=22;	// handshake protocol
    dest[1]=3;	// tls 1.2
    dest[2]=3;
    dest[3]=((len_of_certs+7)>>8);
    dest[4]=((len_of_certs+7)&0xff);

    /* 2. handshake protocol header */
    dest[5]=11;	// handshake type: certificate
    dest[6]=0;
    dest[7]=((len_of_certs+3)>>8);
    dest[8]=((len_of_certs+3)&0xff);

    /* and now the same length ... a third time! */
    dest[9]=0;
    dest[10]=(len_of_certs>>8);
    dest[11]=(len_of_certs&0xff);
  }
  return 12;
}

