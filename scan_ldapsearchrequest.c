#include <stdlib.h>
#include <string.h>
#include "ldap.h"

#ifdef UNITTEST
void* mycalloc(size_t a,size_t b);
#define calloc mycalloc
#endif

size_t scan_ldapsearchrequest(const char* src,const char* max,
			      struct SearchRequest* s) {
  size_t res,tmp;
  unsigned long etmp;
  signed long ltmp;
  size_t stmp;
  s->attributes=0;
  s->filter=0;
  if (!(res=scan_ldapstring(src,max,&s->baseObject)))	// fail01
    goto error;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp)))	// fail02
    goto error;
  if (etmp>2)						// fail03
    goto error;
  s->scope=etmp; res+=tmp;
  if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp)))	// fail04
    goto error;
  if (etmp>3)						// fail05
    goto error;
  s->derefAliases=etmp; res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&ltmp)) || ltmp<0)	// fail06
    goto error;
  s->sizeLimit=(unsigned long)ltmp;
  res+=tmp;
  if (!(tmp=scan_asn1INTEGER(src+res,max,&ltmp)) || ltmp<0)	// fail07
    goto error;
  s->timeLimit=(unsigned long)ltmp;
  res+=tmp;
  if (!(tmp=scan_asn1BOOLEAN(src+res,max,&s->typesOnly)))	// fail08
    goto error;
  res+=tmp;
  if (!(tmp=scan_ldapsearchfilter(src+res,max,&s->filter)))	// fail09
    goto error;
  res+=tmp;
  /* now for the attributelist */
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&stmp)))		// fail10
    goto error;
  res+=tmp;
  {
    const char* nmax=src+res+stmp;
//#define nmax max
    struct AttributeDescriptionList** a=&s->attributes;
    for (;;) {
      struct string attr_name;

      if (src+res==nmax) break;
      if (!(tmp=scan_ldapstring(src+res,nmax,&attr_name)))	// fail12
	goto error;
      res+=tmp;

      if (matchstring(&attr_name, "dn") == 0)
        continue;
      if (!*a) *a=calloc(1,sizeof(struct AttributeDescriptionList));
      if (!*a)							// fail11
	goto error;

      (*a)->a = attr_name;
      a=&(*a)->next;
    }
  }

  return res;
error:
  free_ldapsearchrequest(s);
  return 0;
}

void free_ldapsearchrequest(struct SearchRequest* s) {
  if (s->attributes)
    free_ldapadl(s->attributes);
  free_ldapsearchfilter(s->filter);
  memset(s,0,sizeof(*s));
}

#ifdef UNITTEST
#undef UNITTEST
#include <string.h>
#include <assert.h>
#include "free_ldapsearchfilter.c"
#include "free_ldapadl.c"
#include "scan_asn1tag.c"
#include "scan_asn1length.c"
#include "scan_ldapava.c"
#include "scan_ldapstring.c"
#include "scan_asn1STRING.c"
#include "scan_asn1tagint.c"
#include "scan_asn1string.c"
#include "scan_asn1SEQUENCE.c"
#include "scan_asn1ENUMERATED.c"
#include "scan_asn1INTEGER.c"
#include "scan_asn1BOOLEAN.c"
#include "scan_asn1int.c"
#include "scan_asn1rawint.c"
#include "scan_ldapsearchfilter.c"

#undef calloc
size_t callocfail=(size_t)-1;
void* mycalloc(size_t a,size_t b) {
  if (--callocfail==0) return 0;
  return calloc(a,b);
}

int main() {
  struct SearchRequest s;
  static char buf[100];
  memcpy(buf,
	 "\x04\x13"			// 0 string (len 19)
	   "ou=blog,d=fefe,c=de"	// 2
	 "\x0a\x01\x02"			// 21 enumerated 2
	 "\x0a\x01\x00"			// 24 enumerated 0
	 "\x02\x01\x00"			// 27 integer 0
	 "\x02\x01\x00"			// 30 integer 0
	 "\x01\x01\x00"			// 33 boolean false
	 "\xa5\x10\x04\x02ts\x04\x0a""1234567890"	// 36 ldapsearchfilter (len 16): ts>=1234567890
	 "\x30\x1c"			// 54 sequence (len 28)
	 "\x04\x04"			// 56 string (len 4)
	   "text"			// 58
	 "\x04\x05"			// 62 string (len 5)
	   "danke"			// 64
	 "\x04\x02"			// 69 string (len 2)
	   "ts"				// 71
	 "\x04\x03"			// 73 string (len 3)
	   "img"			// 75
	 "\x04\x04"			// 78 string (len 4)
	   "href",			// 80
	  84);

  assert(scan_ldapsearchrequest(buf, buf+84, &s) == 84);
  assert(s.baseObject.s==buf+2 && s.baseObject.l==19);
  assert(s.scope==2 && s.derefAliases==0 && s.sizeLimit==0 && s.timeLimit==0 && s.typesOnly==0);
  struct AttributeDescriptionList* a = s.attributes;
  assert(a && a->a.l==4 && a->a.s==buf+58);
  a=a->next;
  assert(a && a->a.l==5 && a->a.s==buf+64);
  a=a->next;
  assert(a && a->a.l==2 && a->a.s==buf+71);
  a=a->next;
  assert(a && a->a.l==3 && a->a.s==buf+75);
  a=a->next;
  assert(a && a->a.l==4 && a->a.s==buf+80 && a->next==0);
  free_ldapsearchrequest(&s);
  callocfail=2; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail11
  callocfail=1; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail09
  buf[79]++; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail12
  buf[55]++; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail10
  buf[35]=2; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail08
  buf[30]=0; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail07
  buf[27]=0; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail06
  buf[26]=5; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail05
  buf[24]=0; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail04
  buf[23]=5; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail03
  buf[21]=0; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail02
  buf[0]=0; assert(scan_ldapsearchrequest(buf, buf+84, &s) == 0);	// fail01
  return 0;
}
#endif
