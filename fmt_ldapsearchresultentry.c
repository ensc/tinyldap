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

int fmt_ldappal(char* dest,struct PartialAttributeList* pal) {
//  int l,l2,sum;
  long sum,l,l2;
  if (!pal) return 0;
  sum=fmt_ldapstring(0,&pal->type);
  /* look how much space the adl needs */
  l=fmt_ldapadl(0,pal->values);
  /* write sequence header */
  l2=fmt_asn1SEQUENCE(dest,l+sum);
  if (dest) {
    fmt_ldapstring(dest+l2,&pal->type);
    dest+=sum+l2;
  }
  sum+=l+l2;
  if (dest) {
    fmt_ldapadl(dest,pal->values);
    dest+=l;
  }
  return sum+fmt_ldappal(dest,pal->next);
}

int fmt_ldapsearchresultentry(char* dest,struct SearchResultEntry* sre) {
  int l,sum=0;
  sum=fmt_ldapstring(dest,&sre->objectName);
  if (dest) dest+=sum;
  l=fmt_asn1SEQUENCE(dest,fmt_ldappal(0,sre->attributes));
  sum+=l; if (dest) dest+=l;
  l=fmt_ldappal(dest,sre->attributes);
  return sum+l;
}
