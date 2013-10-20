#include "ldap.h"

static size_t doit(char* dest,const struct AttributeDescriptionList* adl,int seq) {
  const struct AttributeDescriptionList* x=adl;
  size_t sum=0,tmp;
  while (x) {
    sum+=fmt_asn1OCTETSTRING(0,0,x->a.l);
    x=x->next;
  }
  if (seq)
    tmp=fmt_asn1SEQUENCE(dest,sum);
  else
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

size_t fmt_ldapadl(char* dest,const struct AttributeDescriptionList* adl) {
  return doit(dest,adl,1);
}

size_t fmt_ldapavl(char* dest,const struct AttributeDescriptionList* adl) {
  return doit(dest,adl,0);
}
