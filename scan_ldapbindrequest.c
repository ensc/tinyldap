#include "asn1.h"
#include "ldap.h"

int scan_ldapbindrequest(const char* src,const char* max,
			 unsigned long* version,struct string* name,
			 unsigned long* method) {
  int res,tmp;
  if (!(res=scan_asn1INTEGER(src,max,(signed long*)version))) return 0;
  if (!(tmp=scan_ldapstring(src+res,max,name))) return 0;
  res+=tmp;
  {
    enum asn1_tagclass tc;
    enum asn1_tagtype tt;
    if (!(tmp=scan_asn1tag(src+res,max,&tc,&tt,method))) return 0;
    if (tc!=PRIVATE || tt!=PRIMITIVE) return 0;
  }
  return res;
}
