#include "asn1.h"
#include "ldap.h"

int fmt_ldapadl(char* dest,struct AttributeDescriptionList* adl) {
  struct AttributeDescriptionList* x=adl;
  long sum=0;
  int tmp;
  while (x) {
    sum+=fmt_asn1OCTETSTRING(0,0,x->a.l);
    x=x->next;
  }
  tmp=fmt_asn1SET(dest,sum);
  sum+=tmp;
  if (dest) {
    dest+=tmp;
    x=adl;
    while (x) {
      dest+=fmt_ldapstring(dest,&x->a);
      x=x->next;
    }
  }
  return sum;
}

