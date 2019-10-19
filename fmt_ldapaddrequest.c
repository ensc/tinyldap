#include "ldap.h"
#include <assert.h>
#include <alloca.h>

#include <stdio.h>

size_t fmt_ldapaddrequest(char* dest,const struct AddRequest* a) {
  size_t i,n,l,sum;
  const struct Addition* x;
  size_t* ls;	// lengths of the segments
  char* orig=dest;
  for (x=&a->a, l=0; x; x=x->next, ++l);	// how many additions?
  if (l>1000) return 0;
  // now for each addition, calculate size of sequence
  ls = (size_t*)alloca(l*sizeof(size_t));
  for (x=&a->a, sum=i=0; x; x=x->next, ++i) {
    ls[i] = fmt_ldapstring(NULL, &x->AttributeDescription) +
      fmt_ldapavl(NULL, &x->vals);
    sum += ls[i] + fmt_asn1SEQUENCE(NULL, ls[i]);;
  }
  n=fmt_ldapstring(dest,&a->entry);
  if (!dest)
    return n + fmt_asn1SEQUENCE(NULL, sum) + sum;
  dest += n;
  dest += fmt_asn1SEQUENCE(dest, sum);
  for (x=&a->a, i=0; x; x=x->next, ++i) {
    dest += fmt_asn1SEQUENCE(dest, ls[i]);
    dest += fmt_ldapstring(dest, &x->AttributeDescription);
    dest += fmt_ldapavl(dest, &x->vals);
  }
//  assert(n + fmt_asn1SEQUENCE(NULL, sum) + sum == (size_t)(dest-orig));
  return dest-orig;
}

