#include <byte.h>
#include "asn1.h"
#include "ldap.h"
#include <stdlib.h>

/*
        Filter ::= CHOICE {
                and             [0] SET OF Filter,
                or              [1] SET OF Filter,
                not             [2] Filter,
                equalityMatch   [3] AttributeValueAssertion,
                substrings      [4] SubstringFilter,
                greaterOrEqual  [5] AttributeValueAssertion,
                lessOrEqual     [6] AttributeValueAssertion,
                present         [7] AttributeDescription,
                approxMatch     [8] AttributeValueAssertion,
                extensibleMatch [9] MatchingRuleAssertion }
*/

int fmt_ldapsubstring(char* dest,struct Substring* s) {
  long sum=0,tmp=0;
  while (s) {
    tmp=fmt_asn1string(dest,PRIVATE,PRIMITIVE,s->substrtype,s->s.s,s->s.l);
    if (dest) dest+=tmp; sum+=tmp;
    s=s->next;
  }
  return sum;
}

int fmt_ldapsearchfilter(char* dest,struct Filter* f) {
  long sum,tmp,tmp2=0;
  switch (f->type) {
  case AND: case OR: case NOT:
    sum=fmt_ldapsearchfilter(dest,f->x); break;
  case EQUAL: case GREATEQUAL: case LESSEQUAL: case APPROX:
    sum=fmt_ldapava(dest,&f->ava); break;
  case SUBSTRING:
    {
      char* nd=dest;
      long l=0,tmp=0;

      tmp=fmt_ldapsubstring(0,f->substrings);
      l=fmt_ldapstring(nd,&f->ava.desc);
      l+=fmt_asn1SEQUENCE(nd+l,tmp);
      l+=fmt_ldapsubstring(nd+l,f->substrings);
      sum=l;
    }
    break;
  case PRESENT:
//    sum=fmt_ldapstring(dest,&f->ava.desc);
    return fmt_asn1string(dest,PRIVATE,PRIMITIVE,f->type,f->ava.desc.s,f->ava.desc.l);
    break;
  default: return 0;
  }
  tmp=fmt_asn1length(0,sum);
  if (!dest) return sum+tmp+1;
  if (dest) byte_copyr(dest+tmp+1,sum,dest);
  fmt_asn1tag(dest,PRIVATE,CONSTRUCTED,f->type);
  fmt_asn1length(dest+1,sum);
  if (f->next) tmp2=fmt_ldapsearchfilter(dest+sum+tmp+1,f->next);
  return sum+tmp+tmp2+1;
}
