#include "asn1.h"
#include "ldap.h"

int scan_ldapbindresponse(const char* src,const char* max,
			  long* result,struct string* matcheddn,
			  struct string* errormessage,struct string* referral) {
  int res,tmp;
  if (!(res=scan_asn1ENUMERATED(src,max,result))) return 0;
  if (!(tmp=scan_asn1STRING(src+res,max,&matcheddn->s,&matcheddn->l))) return 0;
  res+=tmp;
  if (src+res<max) {
    if (!(tmp=scan_asn1STRING(src+res,max,&errormessage->s,&errormessage->l))) return 0;
    res+=tmp;
  } else {
    errormessage->s=0; errormessage->l=0;
  }
  if (src+res<max) {
    if (!(tmp=scan_asn1STRING(src+res,max,&referral->s,&referral->l))) return 0;
    res+=tmp;
  } else {
    referral->s=0; referral->l=0;
  }
  return res;
}
