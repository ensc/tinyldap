
#include "asn1.h"
#include "ldap.h"

int fmt_ldapbindresponse(char* dest,long result,char* matcheddn,char* errormessage,char* referral) {
  int l,sum=0;
  int nlen;
  sum=l=fmt_asn1ENUMERATED(dest,result);
  if (dest) dest+=l;
  nlen=strlen(matcheddn);
  l=fmt_asn1OCTETSTRING(dest,matcheddn,nlen);
  sum+=l+nlen; if (dest) dest+=l+nlen;
  nlen=strlen(errormessage);
  l=fmt_asn1OCTETSTRING(dest,errormessage,nlen);
  sum+=l+nlen; if (dest) dest+=l+nlen;
  nlen=strlen(referral);
  l=fmt_asn1OCTETSTRING(dest,referral,nlen);
  if (dest) dest+=l+nlen;
  return sum+l+nlen;
}
