#include <string.h>
#include "tinytls.h"

size_t fmt_tls_alert_pkt(char* dest,enum alertlevel level,enum alerttype type) {
  if (dest) {
    memcpy(dest,"\x15\x03\x03\x00\x02",5);
    dest[5]=level;
    dest[6]=type;
  }
  return 7;
}
