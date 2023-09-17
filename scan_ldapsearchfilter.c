#include "ldap.h"
#include <stdlib.h>

#ifdef UNITTEST
void* mycalloc(size_t a,size_t b);
#define calloc mycalloc
#endif

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
  size_t len,res,tmp;
  unsigned long tag;
  const char* nmax;
  *f=0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag)))	// fail01
    goto error;
  if (tc!=PRIVATE || (tt!=CONSTRUCTED && tag!=7) || tag>9)	// fail02
    goto error;
  if (!(tmp=scan_asn1length(src+res,max,&len)))		// fail03
    goto error;
  res+=tmp;
  nmax=src+res+len;
  if (!(*f=calloc(1,sizeof(struct Filter))))		// fail04
    goto error;
  switch ((*f)->type=tag) {
  case 0:    /*  and             [0] SET OF Filter, */
  case 1:    /*  or              [1] SET OF Filter, */
    (*f)->x=0;
    while (src+res<nmax) {
      struct Filter* F=(*f)->x;
      if (!(tmp=scan_ldapsearchfilter(src+res,nmax,&(*f)->x))) {	// fail05
	(*f)->x=F;
	goto error;
      }
      (*f)->x->next=F;
      res+=tmp;
    }
    break;
  case 2:    /*  not             [2] Filter, */
    if (!(tmp=scan_ldapsearchfilter(src+res,nmax,&(*f)->x)))	// fail06
      goto error;
    if (tmp!=len)						// fail07
      goto error;
    res+=tmp;
    break;
  case 3:    /*  equalityMatch   [3] AttributeValueAssertion, */
  case 5:    /*  greaterOrEqual  [5] AttributeValueAssertion, */
  case 6:    /*  lessOrEqual     [6] AttributeValueAssertion, */
  case 8:    /*  approxMatch     [8] AttributeValueAssertion, */
    if (!(tmp=scan_ldapava(src+res,nmax,&(*f)->ava)))		// fail08
      goto error;
    res+=tmp;
    break;
  case 4:    /*  substrings      [4] SubstringFilter, */
    {
      size_t len2;
      if (!(tmp=scan_ldapstring(src+res,nmax,&(*f)->ava.desc)))	// fail09
	goto error;
      res+=tmp;
      if (!(tmp=scan_asn1SEQUENCE(src+res,nmax,&len2)))		// fail10
	goto error;
      res+=tmp;
      while (src+res<nmax) {
	struct Substring* s=calloc(1,sizeof(struct Substring));
	unsigned long x;
	enum asn1_tagtype tt;
	enum asn1_tagclass tc;
	if (!s)							// fail11
	  goto error;
	if (!(tmp=scan_asn1string(src+res,nmax,&tc,&tt,&x,&s->s.s,&s->s.l)) || x>2) {	// fail12
	  free(s);
	  goto error;
	}
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
  case 9:    /*  extensibleMatch [9] MatchingRuleAssertion */
  default:
    goto error;							// fail14
  }
  return res;
error:
  free_ldapsearchfilter(*f);
  *f=0;
  return 0;
}

#ifdef UNITTEST
#undef UNITTEST
#include <string.h>
#include <assert.h>
#include "free_ldapsearchfilter.c"
#include "scan_asn1tag.c"
#include "scan_asn1length.c"
#include "scan_ldapava.c"
#include "scan_ldapstring.c"
#include "scan_asn1STRING.c"
#include "scan_asn1tagint.c"
#include "scan_asn1string.c"
#include "scan_asn1SEQUENCE.c"

#include <stdio.h>

#undef calloc
size_t callocfail=(size_t)-1;
void* mycalloc(size_t a,size_t b) {
  if (--callocfail==0) return 0;
  return calloc(a,b);
}

int main() {
  struct Filter *f = 0;
  char buf[100];
  strcpy(buf,"\x87\x03""foo");

  // type 7, PRESENT
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 5);	// "(foo=*)" (PRESENT)
  assert(f && f->type==PRESENT && f->ava.desc.l==3 && !memcmp(f->ava.desc.s,"foo",3));
  free_ldapsearchfilter(f); f=0;
  callocfail=1; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail04
  callocfail=(size_t)-1;
  buf[1]=0x7e; assert(scan_ldapsearchfilter(buf, buf+100, &f)==0);	// fail03
  buf[0]=0x27; assert(scan_ldapsearchfilter(buf, buf+100, &f)==0);	// middle fail02
  buf[0]=0x8a; assert(scan_ldapsearchfilter(buf, buf+100, &f)==0);	// right fail02
  buf[0]=0x00; assert(scan_ldapsearchfilter(buf, buf+100, &f)==0);	// left fail02
  buf[0]=0x1f; assert(scan_ldapsearchfilter(buf, buf+1, &f)==0);	// fail01

  // type 2, NOT
  strcpy(buf,"\xa2\x05\x87\x03""foo");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 7);	// "(!(foo=*))" (NOT + PRESENT)
  assert(f && f->type==NOT && f->x->type==PRESENT);
  free_ldapsearchfilter(f); f=0;
  buf[1]=6; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail07
  buf[1]=5;
  buf[2]=0x00; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail06

  buf[0]=0xa9; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// type 9 (extensibleMatch) not implemented, should be rejected, fail14

  // type 1, OR
  strcpy(buf,"\xa1\x0d\x87\5danke\x87\4text");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 15);
  assert(f && f->type==OR && f->x->type==PRESENT && f->x->next->type==PRESENT);
  free_ldapsearchfilter(f); f=0;
  buf[1]=0xc; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail05
  buf[1]=0xd; buf[0]=0xa0; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 15);	// type 0, AND
  assert(f && f->type==AND && f->x->type==PRESENT && f->x->next->type==PRESENT);
  free_ldapsearchfilter(f); f=0;

  // type 3, equalityMatch
  strcpy(buf,"\xa3\x06\x04\x01x\x04\x01y");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 8);
  assert(f && f->type==EQUAL && f->ava.desc.l==1 && f->ava.desc.s[0]=='x' &&
	 f->ava.value.l==1 && f->ava.value.s[0]=='y');
  free_ldapsearchfilter(f); f=0;
  // this also achieves 100% coverge of scan_ldapava:
  buf[1]=5; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail08, fail 2 in scan_ldapava
  buf[1]=2; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail08, fail 1 in scan_ldapava

  // type 5, greaterOrEqual
  strcpy(buf,"\xa5\x06\x04\x01x\x04\x01y");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 8);
  assert(f && f->type==GREATEQUAL && f->ava.desc.l==1 && f->ava.desc.s[0]=='x' &&
	 f->ava.value.l==1 && f->ava.value.s[0]=='y');
  free_ldapsearchfilter(f); f=0;

  // type 6, lessOrEqual
  strcpy(buf,"\xa6\x06\x04\x01x\x04\x01y");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 8);
  assert(f && f->type==LESSEQUAL && f->ava.desc.l==1 && f->ava.desc.s[0]=='x' &&
	 f->ava.value.l==1 && f->ava.value.s[0]=='y');
  free_ldapsearchfilter(f); f=0;

  // type 8, approxMatch
  strcpy(buf,"\xa8\x06\x04\x01x\x04\x01y");
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 8);
  assert(f && f->type==APPROX && f->ava.desc.l==1 && f->ava.desc.s[0]=='x' &&
	 f->ava.value.l==1 && f->ava.value.s[0]=='y');
  free_ldapsearchfilter(f); f=0;

  // type 4, substrings
  strcpy(buf,"\xa4\x0e\x04\5danke\x30\x05\x82\3red");	// "(danke=*red)"
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 16);
  assert(f && f->type==SUBSTRING && f->ava.desc.l==5 && !memcmp(f->ava.desc.s,"danke",5) &&
	 f->substrings->substrtype==suffix && f->substrings->s.l==3 && !memcmp(f->substrings->s.s,"red",3) &&
	 f->substrings->next==0);
  free_ldapsearchfilter(f); f=0;
  callocfail=2;
  assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);			// fail11
  callocfail=(size_t)-1;
  buf[12]=4; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail12
  buf[10]++; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail10
  buf[3]=100; assert(scan_ldapsearchfilter(buf, buf+100, &f) == 0);	// fail09

  return 0;
}
#endif
