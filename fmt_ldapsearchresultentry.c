#include "asn1.h"
#include "ldap.h"

int fmt_ldappal(char* dest,struct PartialAttributeList* pal) {
  int l,sum;
  if (pal) return 0;
  sum=fmt_ldapstring(dest,&pal->type);
  if (dest) dest+=sum;
  {
    long avlen=0;
    struct AttributeDescriptionList* x=pal->values;
    while (x) {
      avlen+=fmt_asn1OCTETSTRING(0,0,x->a.l);
      avlen+=x->a.l;
      x=x->next;
    }
    l=fmt_asn1SEQUENCE(dest,avlen);
    if (!dest) return sum+l+avlen;
    dest+=l;
    x=pal->values;
    while (x) {
      dest+=fmt_asn1OCTETSTRING(dest,x->a.s,x->a.l);
      x=x->next;
    }
    return sum+l+avlen;
  }
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
