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

int scan_ldapsearchfilter(const char* src,const char* max,struct Filter** f) {
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  unsigned long tag,len;
  int res,tmp;
  *f=0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) goto error;
  if (tc!=CONTEXT_SPECIFIC || tt!=CONSTRUCTED || tag>9) goto error;
  if (!(tmp=scan_asn1length(src+res,max,&len))) goto error;
  res+=tmp;
  if (src+res+len>max) goto error;
  if (!(*f=malloc(sizeof(struct Filter)))) goto error;
  switch ((*f)->type=tag) {
  case 0:    /*  and             [0] SET OF Filter, */
    goto error;
  case 1:    /*  or              [1] SET OF Filter, */
    goto error;
  case 2:    /*  not             [2] Filter, */
    {
      if (!(tmp=scan_ldapsearchfilter(src+res,src+res+len,&(*f)->x))) goto error;
      if (tmp!=len) goto error;
    }
  case 3:    /*  equalityMatch   [3] AttributeValueAssertion, */
    goto error;
  case 4:    /*  substrings      [4] SubstringFilter, */
    {
      const char* nmax=src+res+len;
      long len2;
      if (!(tmp=scan_ldapstring(src+res,nmax,&(*f)->ava.desc))) goto error;
      res+=tmp;
      if (!(tmp=scan_asn1SEQUENCE(src+res,nmax,&len2))) goto error;
      if (src+tmp+len2!=nmax) goto error;
      goto error;
    }
  case 5:    /*  greaterOrEqual  [5] AttributeValueAssertion, */
    goto error;
  case 6:    /*  lessOrEqual     [6] AttributeValueAssertion, */
    goto error;
  case 7:    /*  present         [7] AttributeDescription, */
    goto error;
  case 8:    /*  approxMatch     [8] AttributeValueAssertion, */
    goto error;
  case 9:    /*  extensibleMatch [9] MatchingRuleAssertion } */
    goto error;
  }
  return res;
error:
  freefilter((*f));
  return 0;
}
