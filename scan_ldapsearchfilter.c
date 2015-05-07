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

        SubstringFilter ::= SEQUENCE {
                type            AttributeDescription,
                -- at least one must be present
                substrings      SEQUENCE OF CHOICE {
                        initial [0] LDAPString,
                        any     [1] LDAPString,
                        final   [2] LDAPString } }

        MatchingRuleAssertion ::= SEQUENCE {
                matchingRule    [1] MatchingRuleId OPTIONAL,
                type            [2] AttributeDescription OPTIONAL,
                matchValue      [3] AssertionValue,
                dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/

size_t scan_ldapsearchfilter(const char* src,const char* max,struct Filter** f) {
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  size_t tag,len,res,tmp;
  const char* nmax;
  *f=0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) goto error;
  if (tc!=PRIVATE || (tt!=CONSTRUCTED && tag!=7) || tag>9) goto error;
  if (!(tmp=scan_asn1length(src+res,max,&len))) goto error;
  res+=tmp;
  nmax=src+res+len;
  if (nmax>max) goto error;
  if (!(*f=malloc(sizeof(struct Filter)))) goto error;
  (*f)->next=0;
  (*f)->x=0;
  (*f)->substrings=0;
  switch ((*f)->type=tag) {
  case 0:    /*  and             [0] SET OF Filter, */
  case 1:    /*  or              [1] SET OF Filter, */
    (*f)->x=0;
    while (src+res<nmax) {
      struct Filter* F=(*f)->x;
      if (!(tmp=scan_ldapsearchfilter(src+res,nmax,&(*f)->x))) {
	if (F) {	/* OK, end of sequence */
	  (*f)->x=F;
	  break;
	}
	(*f)->x=F;
	goto error;
      }
      (*f)->x->next=F;
      res+=tmp;
    }
    break;
  case 2:    /*  not             [2] Filter, */
    if (!(tmp=scan_ldapsearchfilter(src+res,nmax,&(*f)->x))) goto error;
    if (tmp!=len) goto error;
    res+=tmp;
    break;
  case 3:    /*  equalityMatch   [3] AttributeValueAssertion, */
  case 5:    /*  greaterOrEqual  [5] AttributeValueAssertion, */
  case 6:    /*  lessOrEqual     [6] AttributeValueAssertion, */
  case 8:    /*  approxMatch     [8] AttributeValueAssertion, */
    if (!(tmp=scan_ldapava(src+res,nmax,&(*f)->ava))) goto error;
    res+=tmp;
    break;
  case 4:    /*  substrings      [4] SubstringFilter, */
    {
      size_t len2;
      if (!(tmp=scan_ldapstring(src+res,nmax,&(*f)->ava.desc))) goto error;
      res+=tmp;
      if (!(tmp=scan_asn1SEQUENCE(src+res,nmax,&len2))) goto error;
      res+=tmp;
      if (src+res+len2!=nmax) goto error;
      while (src+res<nmax) {
	struct Substring* s=malloc(sizeof(struct Substring));
	unsigned long x;
	enum asn1_tagtype tt;
	enum asn1_tagclass tc;
	if (!s) goto error;
	if (!(tmp=scan_asn1string(src+res,nmax,&tc,&tt,&x,&s->s.s,&s->s.l))) { free(s); goto error; }
	if (x>2) goto error;
	s->substrtype=x;
	res+=tmp;
	s->next=(*f)->substrings;
	(*f)->substrings=s;
      }
      break;
    }
  case 7:    /*  present         [7] AttributeDescription, */
    (*f)->ava.desc.s=src+res;
    (*f)->ava.desc.l=len;
    res+=len;
    break;
  case 9:    /*  extensibleMatch [9] MatchingRuleAssertion } */
    goto error;
  }
  return res;
error:
  free_ldapsearchfilter(*f);
  *f=0;
  return 0;
}
