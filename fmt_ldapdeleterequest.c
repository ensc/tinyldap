#include <string.h>
#include "ldap.h"
#include <libowfat/byte.h>

size_t fmt_ldapdeleterequest(char* dest,const struct string* s) {
  if (dest) byte_copy(dest,s->l,s->s);
  return s->l;
}
