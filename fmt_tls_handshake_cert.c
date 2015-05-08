#include "tinytls.h"
#include <string.h>

size_t fmt_tls_handshake_cert(char* dest,const char* cert,size_t len) {
  if (len>0x1000) return 0;	// completely arbitrary decision on my part
  if (dest) {
    dest[0]=0;
    dest[1]=(len>>8);
    dest[2]=(len&0xff);
    memcpy(dest+3,cert,len);
  }
  return len+3;
}
