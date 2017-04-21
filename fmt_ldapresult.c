#include "ldap.h"
#include <libowfat/str.h>

size_t fmt_ldapresult(char* dest,long result,const char* matcheddn,const char* errormessage,const char* referral) {
  size_t l,sum=0,nlen;
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
    sum+=l;
  }
  return sum;
}
