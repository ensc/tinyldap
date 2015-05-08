#include "tinytls.h"
#include <string.h>

size_t fmt_tls_serverhellodone(char* dest) {
  if (dest)
    memcpy(dest,"\x16\x03\x03\x00\x04\x0e\x00\x00",9);
  return 9;
}
