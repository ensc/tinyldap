#include "asn1.h"
#include "ldap.h"
#include "str.h"

int fmt_ldapresult(char* dest,long result,char* matcheddn,char* errormessage,char* referral) {
  int l,sum=0;
  int nlen;
  sum=l=fmt_asn1ENUMERATED(dest,result);
  if (dest) dest+=l;
  nlen=str_len(matcheddn);
  l=fmt_asn1OCTETSTRING(dest,matcheddn,nlen);
  sum+=l; if (dest) dest+=l;
  nlen=str_len(errormessage);
  l=fmt_asn1OCTETSTRING(dest,errormessage,nlen);
  sum+=l; if (dest) dest+=l;
  if (referral && *referral) {
    nlen=str_len(referral);
    l=fmt_asn1OCTETSTRING(dest,referral,nlen);
    sum+=l; if (dest) dest+=l;
  }
  return sum;
}
