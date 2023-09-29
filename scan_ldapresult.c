#include "ldap.h"

size_t scan_ldapresult(const char* src,const char* max,unsigned long* result,
		       struct string* matcheddn,struct string* errormessage,
		       struct string* referral) {
  size_t res,tmp;
  if (!(res=scan_asn1ENUMERATED(src,max,result)))	// fail01
    return 0;
  if (!(tmp=scan_ldapstring(src+res,max,matcheddn)))	// fail02
    return 0;
  res+=tmp;
  if (!(tmp=scan_ldapstring(src+res,max,errormessage)))	// fail03
    return 0;
  res+=tmp;
  if (src+res==max) {					// case01
    referral->l=0;
    referral->s=0;
    return res;
  }
  if (!(tmp=scan_ldapstring(src+res,max,referral)))	// fail04
    return 0;
  return res+tmp;
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
#include "scan_asn1int.c"
#include "scan_asn1rawint.c"
#include "scan_asn1ENUMERATED.c"

int main() {
  char buf[]="\x0a\x01\x00"	// 0 enumerated 0
    "\x04\x03"			// 3 string (len 3)
      "foo"			// 5
    "\x04\x03"			// 8 string (len 3)
      "bar"			// 10
    "\x04\x03"			// 13 string (len 3)
      "baz";			// 15
  struct string dn, msg, ref;
  unsigned long r;

  assert(scan_ldapresult(buf,buf+13,&r,&dn,&msg,&ref) == 13);	// case01
  assert(r==0 && dn.l==3 && dn.s==buf+5 && msg.l==3 && msg.s==buf+10 && ref.l==0 && ref.s==0);
  assert(scan_ldapresult(buf,buf+18,&r,&dn,&msg,&ref) == 18);
  assert(r==0 && dn.l==3 && dn.s==buf+5 && msg.l==3 && msg.s==buf+10 && ref.l==3 && ref.s==buf+15);

  buf[14]++; assert(scan_ldapresult(buf,buf+18,&r,&dn,&msg,&ref) == 0);	// fail04
  buf[8]=0; assert(scan_ldapresult(buf,buf+18,&r,&dn,&msg,&ref) == 0);	// fail03
  buf[3]=0; assert(scan_ldapresult(buf,buf+18,&r,&dn,&msg,&ref) == 0);	// fail02
  buf[0]=0; assert(scan_ldapresult(buf,buf+18,&r,&dn,&msg,&ref) == 0);	// fail01

  return 0;
}
#endif
