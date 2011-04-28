#include "ldap.h"

size_t scan_ldapmessage(const char* src,const char* max,
			unsigned long* messageid,unsigned long* op,size_t* len) {
  size_t res,tmp;
  if (!(res=scan_asn1SEQUENCE(src,max,len))) goto error;
  if (!(tmp=scan_asn1INTEGER(src+res,max,(long*)messageid))) goto error;
  res+=tmp;
  {
    enum asn1_tagclass tc;
    enum asn1_tagtype tt;
    if (!(tmp=scan_asn1tag(src+res,max,&tc,&tt,op))) goto error;
    if (tc!=APPLICATION) goto error;
    res+=tmp;
    if (!(tmp=scan_asn1length(src+res,max,len))) goto error;
    res+=tmp;
  }
  return res;
error:
  return 0;
}
