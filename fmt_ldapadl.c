#include "asn1.h"
#include "ldap.h"

static int doit(char* dest,struct AttributeDescriptionList* adl,int seq) {
  struct AttributeDescriptionList* x=adl;
  long sum=0;
  int tmp;
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

int fmt_ldapadl(char* dest,struct AttributeDescriptionList* adl) {
  return doit(dest,adl,1);
}

int fmt_ldapavl(char* dest,struct AttributeDescriptionList* adl) {
  return doit(dest,adl,0);
}
