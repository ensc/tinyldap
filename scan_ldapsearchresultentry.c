#include <stdlib.h>
#include "ldap.h"

size_t scan_ldapsearchresultentry(const char* src,const char* max,struct SearchResultEntry* sre) {
  size_t res,tmp,oslen; /* outer sequence length */
  struct PartialAttributeList** a=&sre->attributes;
  *a=0;
  if (!(res=scan_ldapstring(src,max,&sre->objectName))) goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen))) goto error;
  res+=tmp;
  if (src+res+oslen>max) goto error;
  max=src+res+oslen;	/* we now may have a stronger limit */
  while (src+res<max) {
    struct string s;
    struct AttributeDescriptionList* x;
    size_t islen;
    const char* nmax;
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen))) goto error;
    res+=tmp; nmax=src+res+islen; if (nmax>max) goto error;
    if (!(tmp=scan_ldapstring(src+res,nmax,&s))) goto error;
    if (!(*a=malloc(sizeof(struct PartialAttributeList)))) goto error;
    (*a)->next=0; (*a)->values=0; (*a)->type=s;
    res+=tmp;
    if (!(tmp=scan_asn1SET(src+res,max,&islen))) goto error;
    res+=tmp; if (src+res+islen!=nmax) goto error;
    while (src+res<nmax) {
      if (!(tmp=scan_ldapstring(src+res,max,&s))) goto error;
      if (!(x=malloc(sizeof(struct AttributeDescriptionList)))) goto error;
      x->a=s;
      x->next=(*a)->values;
      (*a)->values=x;
      res+=tmp;
    }
    a=&(*a)->next;
  }
  *a=0;
  return res;
error:
  freepal(sre->attributes);
  sre->attributes=0;
  return 0;
}

