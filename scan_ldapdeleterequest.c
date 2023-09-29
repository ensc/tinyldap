#include "ldap.h"

size_t scan_ldapdeleterequest(const char* src,const char* max,
			      struct string* s) {
  if (src>=max) return 0;
  s->l=max-src;
  s->s=src;
  return s->l;
}

#ifdef UNITTEST
#include <assert.h>

int main() {
  char buf[100] = "foo";
  struct string s;
  assert(scan_ldapdeleterequest(buf,buf+3,&s) == 3);
  assert(s.s==buf && s.l==3);
  return 0;
}
#endif
