#include "bstr.h"
#include "uint32.h"

const char* bstrfirst(const char* a) {
  if (*a) return a; else return a+5;
}
