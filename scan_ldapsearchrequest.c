#include "asn1.h"
#include "ldap.h"

int scan_ldapsearchrequest(const char* src,const char* max,
			 struct SearchRequest* s) {
  int res,tmp;
  unsigned long etmp;
  if (!(res=scan_ldapstring(src,max,s->LDAPDN))) goto error;
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
  /* TODO: parse attributedescriptionlist */
  return res;
error:
  return 0;
}
