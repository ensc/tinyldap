#include <stdlib.h>
#include "asn1.h"
#include "ldap.h"

int scan_ldapsearchrequest(const char* src,const char* max,
			 struct SearchRequest* s) {
  int res,tmp;
  unsigned long etmp;
  if (!(res=scan_ldapstring(src,max,&s->baseObject))) goto error;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp))) goto error;
  if (etmp>2) goto error; s->scope=etmp; res+=tmp;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp))) goto error;
  if (etmp>3) goto error; s->derefAliases=etmp; res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&s->sizeLimit))) goto error;
  res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&s->timeLimit))) goto error;
  res+=tmp;
  if (!(tmp=scan_asn1BOOLEAN(src+res,max,&s->timeLimit))) goto error;
  res+=tmp;
  if (!(tmp=scan_ldapsearchfilter(src+res,max,&s->filter))) goto error;
  res+=tmp;
  /* now for the attributelist */
#if 1
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&etmp))) goto error;
  res+=tmp;
#endif
  {
    const char* nmax=src+res+etmp;
//#define nmax max
    struct AttributeDescriptionList** a=&s->attributes;
    if (nmax>max) goto error;
    for (;;) {
      if (src+res>nmax) goto error;
      if (src+res==nmax) break;
      if (!*a) *a=malloc(sizeof(struct AttributeDescriptionList));
      if (!*a) goto error;
      (*a)->next=0;
      if (!(tmp=scan_ldapstring(src+res,nmax,&(*a)->a))) goto error;
      res+=tmp;
      a=&(*a)->next;
    }
    /* TODO: parse attributedescriptionlist */
    return res;
  }
error:
  return 0;
}
