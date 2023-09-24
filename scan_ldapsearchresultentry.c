#include <stdlib.h>
#include "ldap.h"

#ifdef UNITTEST
void* mycalloc(size_t a,size_t b);
#define calloc mycalloc
#endif

size_t scan_ldapsearchresultentry(const char* src,const char* max,struct SearchResultEntry* sre) {
  size_t res,tmp,oslen; /* outer sequence length */
  struct PartialAttributeList** a=&sre->attributes;
  *a=0;
  if (!(res=scan_ldapstring(src,max,&sre->objectName)))	// fail01
    goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen)))	// fail02
    goto error;
  res+=tmp;
  if (src+res+oslen != max)				// fail03
    goto error;
  max=src+res+oslen;	/* we now may have a stronger limit */
  while (src+res<max) {
    struct string s;
    struct AttributeDescriptionList** x;
    size_t islen;
    const char* nmax;
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen)))	// fail04
      goto error;
    res+=tmp;
    nmax=src+res+islen;
    if (!(tmp=scan_ldapstring(src+res,nmax,&s)))	// fail05
      goto error;
    if (!(*a=calloc(1,sizeof(struct PartialAttributeList))))	// fail06
      goto error;
    (*a)->next=0; (*a)->values=0; (*a)->type=s;
    x = &(*a)->values;
    res+=tmp;
    if (!(tmp=scan_asn1SET(src+res,nmax,&islen)))	// fail07
      goto error;
    res+=tmp;
    if (src+res+islen!=nmax)				// fail08
      goto error;
    while (src+res<nmax) {
      if (!(tmp=scan_ldapstring(src+res,max,&s)))	// fail09
	goto error;
      if (!((*x)=calloc(1,sizeof(struct AttributeDescriptionList))))	//fail10
	goto error;
      (*x)->a=s;
      x = &(*x)->next;
      res+=tmp;
    }
    a=&(*a)->next;
  }
  *a=0;
  return res;
error:
  freepal(sre->attributes);
  sre->attributes=0;
  return 0;
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>
#include <string.h>
#include "freepal.c"
#include "scan_ldapstring.c"
#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"
#include "scan_asn1SEQUENCE.c"
#include "scan_asn1SET.c"
#include "free_ldapsearchresultentry.c"

#undef calloc
size_t callocfail=0;
void* mycalloc(size_t a,size_t b) {
  if (--callocfail==0) return 0;
  return calloc(a,b);
}

int main() {
  static char buf[512];
  memcpy(buf,
	 "\x04\x21"		// 0 string (len 33)
	   "ts=1234567890,ou=blog,d=fefe,c=de"
	 "\x30\x81\xc5"		// 35 sequence (len 197)
	 "\x30\x81\xae"		// 38 sequence (len 174)
	 "\x04\x04"		// 41 string (len 4)
	   "text"
	 "\x31\x81\xa5"		// 47 set (len 165)
	 "\x04\x81\xa2"		// 50 string (len 162)
	   "<a href=\"https://www.theverge.com/2023/9/21/23883565/apple-5g-modem-failure-inside-story\">Apple konnte kein eigenes 5G-Modem bauen, kauft weiter bei Qualcomm</a>."
	 "\x30\x12"		// 215 sequence (len 18)
	 "\x04\x02"		// 217 string (len 2)
	   "ts"
	 "\x31\x0c"		// 221 set (len 12)
	 "\x04\x0a"		// 223 string (len 10)
	   "1234567890",
	 235);
  struct SearchResultEntry s;
  assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 235);
  assert(s.objectName.s==buf+2 && s.objectName.l==33);
  assert(s.attributes && s.attributes->type.s==buf+43 && s.attributes->type.l==4);
  assert(s.attributes->values && s.attributes->values->a.s==buf+53 && s.attributes->values->a.l==162 && s.attributes->values->next==0);
  assert(s.attributes->next && s.attributes->next->type.s==buf+219 && s.attributes->next->type.l==2 && s.attributes->next->next==0);
  assert(s.attributes->next->values && s.attributes->next->values->a.s==buf+225 && s.attributes->next->values->a.l==10 && s.attributes->next->values->next==0);
  free_ldapsearchresultentry(&s);

  callocfail=2; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);	// fail10
  callocfail=1; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);	// fail06
  buf[224]++; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail09
  buf[222]--; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail08
  buf[222]++; buf[221]=0x30; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail07
  buf[217]=0; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail05
  buf[215]=0; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail04
  buf[37]--; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail03
  buf[35]=0; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail02
  buf[0]=0; assert(scan_ldapsearchresultentry(buf,buf+235,&s) == 0);		// fail01
  return 0;
}

#endif
