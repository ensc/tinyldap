#include <stdarg.h>
#include <string.h>
#include "asn1.h"

size_t fmt_asn1generic(char* dest,const char* fmt,...) {
  size_t containerstack[100];
  size_t curinstack=0;
  va_list args;
  va_start(args,fmt);
  unsigned long* application=0;
  struct string* s;
  struct string S;
  size_t curlen=0;
  size_t cursor=0;
  size_t seqlen;
  unsigned long appstore;
  while (*fmt) {
    char* realdest=dest?dest+cursor:NULL;
    switch (*fmt) {
    case 'a':	// make next tag use APPLICATION with this tag
      appstore=va_arg(args,unsigned long);
      application=&appstore;
      break;
    case 'i':	// send integer
      {
	unsigned long i=va_arg(args,unsigned long);
	if (application)
	  curlen=fmt_asn1int(realdest,APPLICATION,PRIMITIVE,*application,i);
	else
	  curlen=fmt_asn1int(realdest,UNIVERSAL,PRIMITIVE,INTEGER,i);
	application=NULL;
	break;
      }
    case 'S':	// send OCTET_STRING, using struct string* as arg
      s=va_arg(args,struct string*);
copystring:
      if (application)
	curlen=fmt_asn1string(realdest,APPLICATION,PRIMITIVE,*application,s->s,s->l);
      else
	curlen=fmt_asn1string(realdest,UNIVERSAL,PRIMITIVE,OCTET_STRING,s->s,s->l);
      application=NULL;
      break;
    case 's':	// send OCTET_STRING, using const char* with strlen() as arg
      S.s=va_arg(args,const char*);
      S.l=strlen(S.s);
      s=&S;
      goto copystring;
    case '{':	// start SEQUENCE
      if (application)
	curlen=fmt_asn1tag(realdest,APPLICATION,CONSTRUCTED,*application);
      else
	curlen=fmt_asn1tag(realdest,UNIVERSAL,CONSTRUCTED,SEQUENCE_OF);
      containerstack[curinstack++]=cursor+curlen;
      application=NULL;
      break;
    case '}':	// end of SEQUENCE
      /* we just wrote the tag and the sequence.  Now that we wrote the
       * sequence, we know the length it took, and we need to move the
       * sequence data backwards to make room to write the ASN.1 length */
      {
	char* anfang;
	if (!curinstack) return 0;
	anfang=dest+containerstack[--curinstack];
	seqlen=dest+cursor-anfang;
	curlen=fmt_asn1length(NULL,seqlen);
	if (!dest) break;
	memmove(anfang+curlen,anfang,seqlen);
	fmt_asn1length(anfang,seqlen);
	break;
      }
    }
    cursor+=curlen;
    ++fmt;
  }
  return cursor;
}
