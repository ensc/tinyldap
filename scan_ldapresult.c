#include "asn1.h"
#include "ldap.h"

unsigned int scan_ldapresult(const char* src,const char* max,long* result,
		    struct string* matcheddn,struct string* errormessage,
		    struct string* referral) {
  unsigned int res,tmp;
  if (!(res=scan_asn1ENUMERATED(src,max,result))) return 0;
  if (!(tmp=scan_ldapstring(src+res,max,matcheddn))) return 0;
  res+=tmp;
  if (!(tmp=scan_ldapstring(src+res,max,errormessage))) return 0;
  res+=tmp;
  if (src+res==max) { referral->l=0; referral->s=0; return res; }
  if (!(tmp=scan_ldapstring(src+res,max,referral))) return 0;
  return res+tmp;
}
