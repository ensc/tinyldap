#include <stdlib.h>
#include <libowfat/byte.h>
#include "ldap.h"

/*
        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
                object          LDAPDN,
                modification    SEQUENCE OF SEQUENCE {
                        operation       ENUMERATED {
                                                add     (0),
                                                delete  (1),
                                                replace (2) },
                        modification    AttributeTypeAndValues } }

        AttributeTypeAndValues ::= SEQUENCE {
                type    AttributeDescription,
                vals    SET OF AttributeValue }
*/

#ifdef UNITTEST
size_t mallocfail=0;
static void* mymalloc(size_t n) {
  if (--mallocfail == 0) return 0;
  return malloc(n);
}
#define malloc mymalloc
#endif

size_t scan_ldapmodifyrequest(const char* src,const char* max,struct ModifyRequest* m) {
  size_t res,tmp,oslen; /* outer sequence length */
  struct Modification* last=0;
  byte_zero(m,sizeof(*m));
  if (!(res=scan_ldapstring(src,max,&m->object)))				// fail01
    goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen)))				// fail02
    goto error;
  res+=tmp;
  max=src+res+oslen;
  if (src+res>=max)								// fail03
    goto error;		/* need at least one record */
  do {
    size_t islen;
    unsigned long etmp;
    if (last) {
      struct Modification* cur;
      if (!(cur=malloc(sizeof(struct Modification))))				// fail04
	goto error;
      byte_zero(cur,sizeof(*cur));
      last->next=cur; last=cur;
    } else
      last=&m->m;
    last->next=0;
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen)))				// fail05
      goto error;
    res+=tmp;
    if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp)))				// fail06
      goto error;
    if (etmp>2)									// fail06b
      goto error;
    last->operation=etmp; res+=tmp;
    {
      size_t iislen;	/* urgh, _three_ levels of indirection */
      const char* imax;
      if (!(tmp=scan_asn1SEQUENCE(src+res,max,&iislen)))			// fail07
	goto error;
      res+=tmp;
      imax=src+res+iislen;
      if (!(tmp=scan_ldapstring(src+res,imax,&last->AttributeDescription)))	// fail08
	goto error;
      res+=tmp;
      {
	size_t iiislen;	/* waah, _four_ levels of indirection!  It doesn't get more inefficient than this */
	const char* iimax;
	struct AttributeDescriptionList** ilast=0;
	if (!(tmp=scan_asn1SET(src+res,max,&iiislen)))				// fail09
	  goto error;
	res+=tmp;
	iimax=src+res+iiislen;
	if (src+res+iiislen!=imax)						// fail10
	  goto error;
	ilast=&last->vals;
	while (src+res<iimax) {
	  if (!(*ilast=malloc(sizeof(struct AttributeDescriptionList))))	// fail11
	    goto error;
	  byte_zero(*ilast,sizeof(**ilast));
	  if (!(tmp=scan_ldapstring(src+res,imax,&(*ilast)->a)))		// fail12
	    goto error;
	  ilast=&(*ilast)->next;
	  res+=tmp;
	}
      }
    }
  } while (src+res<max);
  return res;
error:
  free_ldapmodifyrequest(m);
  return 0;
}

static void free_mod(struct Modification* m) {
  while (m) {
    struct Modification* tmp=m->next;
    free_ldapadl(m->vals);
    free(m);
    m=tmp;
  }
}

void free_ldapmodifyrequest(struct ModifyRequest* m) {
  free_ldapadl(m->m.vals);
  free_mod(m->m.next);
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>
#include <string.h>
#include "scan_ldapstring.c"
#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"
#include "scan_asn1SEQUENCE.c"
#include "scan_asn1SET.c"
#include "scan_asn1ENUMERATED.c"
#include "scan_asn1int.c"
#include "scan_asn1rawint.c"
#include "free_ldapadl.c"

void byte_zero(void* out,size_t n) {
  memset(out,0,n);
}

#include <stdio.h>

int main() {
  char buf[500];
  
  memcpy(buf, "\x04\x21ts=1234567890,ou=blog,d=fefe,c=de"	// 0 string (33)
	      "\x30\x16"					// 35 sequence (22)
	      "\x30\x14"					// 37 sequence (20)
	      "\x0a\x01\x02"					// 39 enumerated (1)
	      "\x30\x0f"					// 42 sequence (15)
	      "\x04\x05""danke"					// 44 string (5)
	      "\x31\x06"					// 51 set (6)
	      "\x04\x04""Fefe",					// 53 string (4)
	59);
  struct ModifyRequest m = { 0 };
  assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 59);
  assert(m.object.l==33 && m.object.s==buf+2);
  assert(m.m.operation==Replace && m.m.AttributeDescription.l==5 && m.m.AttributeDescription.s==buf+46);
  assert(m.m.vals && m.m.vals->a.l==4 && m.m.vals->a.s==buf+55 && m.m.vals->next==0);
  free_ldapmodifyrequest(&m);
  memcpy(buf+53,"\x04\x01X\x04\x01Y", 6);
  assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 59);
  assert(m.m.vals && m.m.vals->a.l==1 && m.m.vals->a.s==buf+55);
  assert(m.m.vals->next && m.m.vals->next->a.l==1 && m.m.vals->next->a.s==buf+58 && m.m.vals->next->next==0);
  free_ldapmodifyrequest(&m);
  memcpy(buf+59,
	      "\x30\x14"					// 59 sequence (20)
	      "\x0a\x01\x02"					// 61 enumerated (1)
	      "\x30\x0f"					// 64 sequence (15)
	      "\x04\x05""danke"					// 66 string (5)
	      "\x31\x06"					// 73 set (6)
	      "\x04\x04""Fefe",					// 75 string (4)
	 22);
  buf[36]+=22;	// adjust length of outer sequence
  assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 81);
  free_ldapmodifyrequest(&m);
  mallocfail=2; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail11
  mallocfail=3; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail04
  buf[75]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail12
  buf[36]++; buf[65]++; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail10
  buf[73]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail09
  buf[66]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail08
  buf[64]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail07
  buf[62]=3; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail06b
  buf[61]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail06
  buf[59]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail05
  memcpy(buf, "\x04\x21ts=1234567890,ou=blog,d=fefe,c=de"	// 0 string (33)
	      "\x30\x00",					// 35 sequence (0)
	      37);
  assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);			// fail03
  buf[35]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail02
  buf[0]=0; assert(scan_ldapmodifyrequest(buf,buf+500,&m) == 0);	// fail01
  return 0;
}

#endif
