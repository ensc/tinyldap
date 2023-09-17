#include <stdlib.h>
#include "ldap.h"
#include <libowfat/buffer.h>
#include <libowfat/byte.h>

#ifdef UNITTEST
size_t mallocfail=0;
static void* mymalloc(size_t n) {
  if (--mallocfail == 0) return 0;
  return malloc(n);
}
#define malloc mymalloc
#endif

/*
        AddRequest ::= [APPLICATION 8] SEQUENCE {
                entry           LDAPDN,
                attributes      SEQUENCE OF SEQUENCE {
                        type            AttributeDescription,
                        vals            SET OF AttributeValue } }

        AttributeList ::= SEQUENCE OF SEQUENCE {
                type    AttributeDescription,
                vals    SET OF AttributeValue }
*/

size_t scan_ldapaddrequest(const char* src,const char* max,struct AddRequest* a) {
  size_t res,tmp,oslen;
  struct Addition* last=0;
  byte_zero(a,sizeof(*a));
  if (!(res=scan_ldapstring(src,max,&a->entry)))	// fail01
    goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen)))	// fail02
    goto error;
  res+=tmp;
  max=src+res+oslen;
  if (src+res>=max)					// fail04
    goto error;		/* need at least one record */
  do {
    size_t islen;
    if (last) {						// case01
      struct Addition* cur;
      if (!(cur=malloc(sizeof(struct Addition))))	// fail05
        goto error;
      last->next=cur;
      last=cur;
    } else {
      last=&a->a;
    }
    byte_zero(last, sizeof(*last));
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen)))	// fail06
      goto error;
    res+=tmp;
    const char* seq_max=src+res+islen;
    /* scan AttributeDescription: */
    if (!(tmp=scan_ldapstring(src+res,max,&last->AttributeDescription)))	// fail07
      goto error;
    res+=tmp;

    /* scan set of AttributeValue: */
    {
      size_t set_len;
      const char* set_max;
      struct AttributeDescriptionList* ilast=0;
      if (!(tmp=scan_asn1SET(src+res,max,&set_len))) {	// fail08
        goto error;
      }
      res+=tmp;
      set_max=src+res+set_len;
      if (seq_max!=set_max) {			// fail09
        goto error;
      }
      while (src+res<set_max) {
        if (ilast) {
          struct AttributeDescriptionList* x;
          if (!(x=malloc(sizeof(struct AttributeDescriptionList))))	// fail10
	    goto error;
          ilast->next=x;
          ilast = ilast->next;
        } else {
          ilast=&last->vals;
        }
	ilast->next=0;
        if (!(tmp=scan_ldapstring(src+res,max,&ilast->a)))	// fail11
          goto error;
        res+=tmp;
      }
    }
  } while (src+res<max);
//  buffer_putsflush(buffer_2,"done with scan_ldapaddrequest!\n");
  return res;
error:
  free_ldapaddrequest(a);
  return 0;
}

static void free_add(struct Addition * a) {
  while (a) {
    struct Addition * tmp = a->next;
    free_ldapadl(a->vals.next);
    free(a);
    a = tmp;
  }
}

void free_ldapaddrequest(struct AddRequest * a) {
  free_ldapadl(a->a.vals.next);
  free_add(a->a.next);
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "scan_ldapstring.c"
#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"
#include "scan_asn1SEQUENCE.c"
#include "scan_asn1SET.c"
#include "free_ldapadl.c"

void byte_zero(void* out,size_t n) {
  memset(out,0,n);
}

int main() {
  static char buf[500]=
    "\x04\x21""ts=1234567890,ou=blog,d=fefe,c=de"	// 0: string(33)
    "\x30\x82\x01\x64"			// 35: sequence(356)
      "\x30\x1a"			// 39: sequence(26)
	"\x04\x0b"			// 41: string(11)
	  "objectClass"			// 43
	"\x31\x0b"			// 54: set(11)
	  "\x04\x09"			// 56: string(9)
	    "blogentry"			// 58
      "\x30\x12"			// 67: sequence(18)
	"\x04\x02"			// 69: string(2)
	  "ts"				// 71
	"\x31\x0c"			// 73: set(12)
	  "\x04\x0a"			// 75: string(10)
	    "1234567890"		// 77
      "\x30\x82\x01\x30"		// 87: sequence(304)
	"\x04\x04"			// 91: string(4)
	  "text"			// 93
	"\x31\x82\x01\x26"		// 97: set(294)
	"\x04\x82\x01\x22"		// 101: string(290)
	  "Ein Leser berichtet:<blockquote>Gestern in einem Regionalzug der \303\226BB:<p>\"Sehr geehrte Fahrg\303\244ste, aufgrund eines Softwarefehlers muss ich das Fahrzeug neu starten. Das hei\303\237t es gehen kurz die Lichter aus, es wird finster, aber es ist alles in Ordnung.\"</blockquote>Kann man nichts machen.";	// 105
  struct AddRequest a = { 0 };
  assert(scan_ldapaddrequest(buf,buf+500,&a) == 395);
  assert(a.entry.l==33 && a.entry.s==buf+2);	// dn
  struct Addition* b=&a.a;
  assert(b->AttributeDescription.l==11 && b->AttributeDescription.s==buf+43);	// "objectClass"
  assert(b->vals.a.l==9 && b->vals.a.s==buf+58 && b->vals.next==0);	// "blogentry"
  b=b->next; assert(b);
  assert(b->AttributeDescription.l==2 && b->AttributeDescription.s==buf+71);	// "ts"
  assert(b->vals.a.l==10 && b->vals.a.s==buf+77 && b->vals.next==0);	// "1234567890"
  b=b->next; assert(b);
  assert(b->AttributeDescription.l==4 && b->AttributeDescription.s==buf+93);	// "text"
  assert(b->vals.a.l==290 && b->vals.a.s==buf+105 && b->vals.next==0);	// "Ein..."
  assert(b->next==0);
  free_ldapaddrequest(&a);
  mallocfail=1; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);	// fail10

  memcpy(buf+75,"\x04\x02xy\x04\x06zyxabc", 12);
  mallocfail=0; assert(scan_ldapaddrequest(buf,buf+500,&a) == 395);	// case01
  b=a.a.next; assert(b);
  assert(b->vals.a.l==2 && b->vals.a.s==buf+77 && b->vals.next);	// "xy"
  assert(b->vals.next->a.l==6 && b->vals.next->a.s==buf+81 && b->vals.next->next==0);	// "zyxabc"
  free_ldapaddrequest(&a);
  mallocfail=2; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);	// fail05

  buf[104]=0x23; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);	// fail11
  buf[100]=0x27; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);	// fail08
  buf[100]=0x25; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);	// fail09
  buf[91]=0; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);		// fail07
  buf[87]=0; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);		// fail06

  strcpy(buf,"\x04\x21""ts=1234567890,ou=blog,d=fefe,c=de"	// 0: string(33)
    "\x30");			// 35: sequence(0), 0 byte implicit because strcpy not memcpy
  assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);			// fail04
  buf[35]=0; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);		// fail02
  buf[0]=0; assert(scan_ldapaddrequest(buf,buf+500,&a) == 0);		// fail01

  return 0;
}

#endif
