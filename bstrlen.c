#include <string.h>
#include "bstr.h"
#include <libowfat/uint32.h>
#include <libowfat/str.h>

size_t bstrlen(const char* a) {
  if (*a) return str_len(a); else return uint32_read(a+1);
}
