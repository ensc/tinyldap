#include <string.h>
#include "bstr.h"
#include "uint32.h"
#include "str.h"

int bstrlen(const char* a) {
  if (*a) return str_len(a); else return uint32_read(a+1);
}
