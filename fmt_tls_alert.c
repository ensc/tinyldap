#include "tinytls.h"

size_t fmt_tls_alert(char* dest,enum alertlevel level,enum alerttype type) {
  if (dest) {
    dest[0]=level;
    dest[1]=type;
  }
  return 2;
}

