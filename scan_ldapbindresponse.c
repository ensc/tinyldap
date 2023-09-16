#include "ldap.h"

size_t scan_ldapbindresponse(const char* src,const char* max,
			     unsigned long* result,struct string* matcheddn,
			     struct string* errormessage,struct string* referral) {
  size_t res,tmp;
  if (!(res=scan_asn1ENUMERATED(src,max,result)))
    return 0;	// fail01
  if (!(tmp=scan_ldapstring(src+res,max,matcheddn)))
    return 0;	// fail02
  res+=tmp;
  if (src+res<max) {
    if (!(tmp=scan_ldapstring(src+res,max,errormessage)))
      return 0;	// fail03
    res+=tmp;
  } else {
    errormessage->s=0; errormessage->l=0;
  }
  if (src+res<max) {
    if (!(tmp=scan_ldapstring(src+res,max,referral)))
      return 0;	// fail04
    res+=tmp;
  } else {
    referral->s=0; referral->l=0;
  }
  return res;
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>

#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"
#include "scan_ldapstring.c"
#include "scan_asn1rawint.c"
#include "scan_asn1int.c"
#include "scan_asn1INTEGER.c"
#include "scan_asn1ENUMERATED.c"

#include <stdio.h>

int main() {
//  static char buf[] = "\n\0010\4\0\4\26authentication failure";	// bind response
  static char buf[] = "\x0a\x01\x31\x04\x00\x04\x16""authentication failure\x04\x00";	// bind response
  unsigned long result;
  struct string matcheddn, errormessage, referral;

  assert(scan_ldapbindresponse(buf,buf+31,&result,&matcheddn,&errormessage,&referral)==31);
  assert(result==49 && matcheddn.l==0 && errormessage.l==22 && errormessage.s==buf+7 && referral.l==0);
  assert(scan_ldapbindresponse(buf,buf+30,&result,&matcheddn,&errormessage,&referral)==0);	// fail04
  assert(scan_ldapbindresponse(buf,buf+29,&result,&matcheddn,&errormessage,&referral)==29);	// without referral
  assert(scan_ldapbindresponse(buf,buf+5,&result,&matcheddn,&errormessage,&referral)==5);	// without errormessage+referral
  assert(scan_ldapbindresponse(buf,buf+28,&result,&matcheddn,&errormessage,&referral)==0);	// fail03
  buf[4]++;
  assert(scan_ldapbindresponse(buf,buf+5,&result,&matcheddn,&errormessage,&referral)==0);	// fail02
  buf[4]--;
  buf[0]=0;
  assert(scan_ldapbindresponse(buf,buf+5,&result,&matcheddn,&errormessage,&referral)==0);	// fail01
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}

#endif
