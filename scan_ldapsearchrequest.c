#include <stdlib.h>
#include <string.h>
#include "ldap.h"

size_t scan_ldapsearchrequest(const char* src,const char* max,
			      struct SearchRequest* s) {
  size_t res,tmp;
  unsigned long etmp;
  signed long ltmp;
  size_t stmp;
  s->attributes=0;
  s->filter=0;
  if (!(res=scan_ldapstring(src,max,&s->baseObject))) goto error;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp))) goto error;
  if (etmp>2) goto error;
  s->scope=etmp; res+=tmp;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp))) goto error;
  if (etmp>3) goto error;
  s->derefAliases=etmp; res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&ltmp)) || ltmp<0) goto error;
  s->sizeLimit=(unsigned long)ltmp;
  res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&ltmp)) || ltmp<0) goto error;
  s->timeLimit=(unsigned long)ltmp;
  res+=tmp;
  if (!(tmp=scan_asn1BOOLEAN(src+res,max,&s->typesOnly))) goto error;
  res+=tmp;
  if (!(tmp=scan_ldapsearchfilter(src+res,max,&s->filter))) goto error;
  res+=tmp;
  /* now for the attributelist */
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&stmp))) goto error;
  res+=tmp;
  {
    const char* nmax=src+res+stmp;
//#define nmax max
    struct AttributeDescriptionList** a=&s->attributes;
    if (nmax>max) goto error;
    for (;;) {
      if (src+res>nmax) goto error;
      if (src+res==nmax) break;
      if (!*a) *a=calloc(1,sizeof(struct AttributeDescriptionList));
      if (!*a) goto error;
      if (!(tmp=scan_ldapstring(src+res,nmax,&(*a)->a))) { goto error; }
      res+=tmp;
      a=&(*a)->next;
    }
    return res;
  }
error:
  free_ldapsearchrequest(s);
  return 0;
}

void free_ldapsearchrequest(struct SearchRequest* s) {
  if (s->attributes)
    free_ldapadl(s->attributes);
  free_ldapsearchfilter(s->filter);
  memset(s,0,sizeof(*s));
}
