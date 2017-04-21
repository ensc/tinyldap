#include "mstorage.h"
#include "mduptab.h"
#include <libowfat/str.h>

long mduptab_adds(mduptab_t* t,const char* s) {
  return mduptab_add(t,s,str_len(s));
}
