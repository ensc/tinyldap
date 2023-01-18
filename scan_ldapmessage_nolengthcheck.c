#include "ldap.h"

size_t scan_ldapmessage_nolengthcheck(const char* src,const char* max,
			unsigned long* messageid,unsigned long* op,size_t* len) {
  size_t res,tmp;
  if (!(res=scan_asn1SEQUENCE_nolengthcheck(src,max,len))) return 0;
  return res;
}
