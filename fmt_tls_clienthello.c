#include "tinytls.h"
#include <libowfat/uint16.h>
#include <libowfat/uint32.h>
#include <time.h>
#include <string.h>

size_t fmt_tls_clienthello(char* dest, struct ssl_context* sc) {
  size_t hnextlen=sc->servername?strlen(sc->servername)+9:0;
  if (hnextlen>0x1000) return 0;
  if (sc->session.l>0xff) return 0;
  if (dest) {
    char* x;
    dest[0]=22;		// content type: handshake
    uint16_pack_big(dest+1,0x303);	// tls 1.2
    // uint16_pack_big(dest+3,length);
    dest[5]=0x01;	// handshake type: client hello
    // uint16_pack_big(dest+6,length);
    uint16_pack_big(dest+9,0x0303);	// tls 1.2
    uint32_pack_big(dest+11,time(0));
    memcpy(dest+15,sc->myrandom,sizeof(sc->myrandom));
    if ((dest[43]=sc->session.l))
      memcpy(dest+44,sc->session.s,sc->session.l);
    x=dest+44+sc->session.l;
    uint16_pack_big(x,6);
    uint16_pack_big(x+2,0x3d);	// TLS_RSA_WITH_AES_256_CBC_SHA256
    uint16_pack_big(x+4,0x35);	// TLS_RSA_WITH_AES_256_CBC_SHA
    uint16_pack_big(x+6,0xff);	// "we support renegotiation"
    x+=8;
#if 0
    memcpy(x,"\x02\x01\x00",3);	// 2 compression methods, deflate and null
    x+=3;
#else
    memcpy(x,"\x01\x00",2);	// only support null compression
    x+=2;
#endif
    uint16_pack_big(x,hnextlen);
    x+=2;
    if (hnextlen) {
      uint16_pack_big(x,0);	// extension id 0 = server_name
      uint16_pack_big(x+2,hnextlen-4);	// length
      uint16_pack_big(x+4,hnextlen-6);	// another length
      x[6]=0;	// hostname type: DNS
      uint16_pack_big(x+7,hnextlen-9);	// yet another length
      memcpy(x+9,sc->servername,hnextlen-9);
      x+=hnextlen;
    }
    uint16_pack_big(dest+3,x-dest-5);
    uint16_pack_big(dest+7,x-dest-9);
    return x-dest;
  } else
    return 44+sc->session.l+8+2+2+hnextlen;
}
