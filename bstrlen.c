#include <string.h>
#include "bstr.h"
#include "uint32.h"

int bstrlen(const char* a) {
  if (*a) return strlen(a); else return uint32_read(a+1);
}
