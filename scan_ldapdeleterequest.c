#include "ldap.h"

size_t scan_ldapdeleterequest(const char* src,const char* max,
			      struct string* s) {
  if (src>=max) return 0;
  s->l=max-src;
  s->s=src;
  return s->l;
}
