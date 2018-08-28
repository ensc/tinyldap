#include "ldap.h"
#include <assert.h>
#include <alloca.h>

#include <stdio.h>

size_t fmt_ldapmodifyrequest(char* dest,const struct ModifyRequest* m) {
  size_t i,n,l,sum;
  const struct Modification* x;
  size_t* ls;	// lengths of the changes
  size_t* lss;	// lengths of the inner sequences in the changes
  char* orig=dest;
  for (x=&m->m, l=0; x; x=x->next, ++l);	// how many changes?
  if (l>1000) return 0;
  // now for each change, calculate size of change sequence
  ls = (size_t*)alloca(l*sizeof(size_t));
  lss = (size_t*)alloca(l*sizeof(size_t));
  for (x=&m->m, sum=i=0; x; x=x->next, ++i) {
    lss[i] = fmt_ldapstring(NULL, &x->AttributeDescription) +
      fmt_ldapavl(NULL, x->vals);
    ls[i] = fmt_asn1ENUMERATED(NULL, x->operation) +
      fmt_asn1SEQUENCE(NULL, lss[i]) +
      lss[i];
    sum += ls[i] + fmt_asn1SEQUENCE(NULL, ls[i]);;
  }
  n=fmt_ldapstring(dest,&m->object);
  if (!dest)
    return n + fmt_asn1SEQUENCE(NULL, sum) + sum;
  dest += n;
  dest += fmt_asn1SEQUENCE(dest, sum);
  for (x=&m->m, i=0; x; x=x->next, ++i) {
    dest += fmt_asn1SEQUENCE(dest, ls[i]);
    dest += fmt_asn1ENUMERATED(dest, x->operation);
    dest += fmt_asn1SEQUENCE(dest, lss[i]);
    dest += fmt_ldapstring(dest, &x->AttributeDescription);
    dest += fmt_ldapavl(dest, x->vals);
  }
  return dest-orig;
}

