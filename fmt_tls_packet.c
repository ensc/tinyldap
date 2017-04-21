#include "tinytls.h"
#include <libowfat/uint16.h>

size_t fmt_tls_packet(char* dest,enum contenttype ct, size_t len) {
  if (len>0xffff) return 0;
  if (dest) {
    dest[0]=ct;
    dest[1]=0x03; dest[2]=0x03;	// version: TLS 1.2
    dest[3]=len>>8;
    dest[4]=len&0xff;
  }
  return 5;
}
