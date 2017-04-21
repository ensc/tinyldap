#include "bstr.h"
#include <libowfat/uint32.h>

size_t bstrstart(const char* a) {
  if (*a) return 0; else return 5;
}
