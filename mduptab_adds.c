#include <stdlib.h>
#include <string.h>
#include "mstorage.h"
#include "mduptab.h"

long mduptab_adds(mduptab_t* t,const char* s) {
  return mduptab_add(t,s,strlen(s));
}
