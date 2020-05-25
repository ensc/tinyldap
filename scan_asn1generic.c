#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include "asn1.h"
#include <string.h>

size_t scan_asn1generic(const char* src,const char* max,const char* fmt,...) {
  size_t curlen,seqlen;
  const char* maxstack[100];
  size_t curmax=0;
  va_list args;
  int optional=0;
  unsigned long* application=NULL;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  unsigned int wantedtag;
  unsigned long* desttag=NULL;
  const char* orig=src;
  va_start(args,fmt);
  maxstack[0]=max;
  while (*fmt) {
    switch (*fmt) {
    case '?':		// ? = rest is optional (until end of sequence)
      optional=1;
      break;
    case 'B':		// B = BOOLEAN
    case 'i':		// i = INTEGER
      {
	long* dest=va_arg(args,long*);
	int* bdest=(int*)dest;
	long l;
	if (*fmt=='B') *bdest=0; else *dest=0;
	curlen=scan_asn1int(src,maxstack[curmax],&tc,&tt,&tag,&l);
	if (application) {
	  if (tc!=APPLICATION) goto error;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=(*fmt=='B'?BOOLEAN:INTEGER))
	    goto error;
	}
	if (!curlen) { if (optional) break; else goto error; }
	if (*fmt=='B')
	  *bdest=l;
	else
	  *dest=l;
	src+=curlen;
	application=NULL;
	break;
      }
    case 'I':		// I = INTEGER, but for bignum integers; writes to an array of size_t, first one contains number of digits after it
      {
	size_t* dest=va_arg(args,size_t*);
	size_t len,tmp,tlen,j,t;
	if (!(len=scan_asn1tag(src,maxstack[curmax],&tc,&tt,&tag))) goto error;
	if (!(tmp=scan_asn1length(src+len,maxstack[curmax],&tlen))) goto error;
	len+=tmp;
	j=0; t=1;
	src+=len;
	/* asn.1 sends n bytes, most significant first.
	 * we want m digits, most significant first.
	 * if n is not a multiple of sizeof(digit) then we need to
	 * insert a few 0 bytes in the first word
	 */
	while (tlen) {
	  j=(j<<8)+(unsigned char)(*src);
	  ++src;
	  --tlen;
	  if ((tlen%sizeof(j))==0 && (j || t>1)) {
	    dest[t]=j;
	    j=0;
	    ++t;
	  }
	}
	if (j) dest[t++]=j;
	dest[0]=t-1;
	break;
      }
    case 'b':
      wantedtag=BIT_STRING; goto stringmain;
    case 'u':
      wantedtag=UTCTIME; goto stringmain;
    case 'p':
      wantedtag=PrintableString; goto stringmain;
    case 'a':
      wantedtag=IA5String; goto stringmain;
    case 's':
      wantedtag=OCTET_STRING; goto stringmain;
stringmain:
      {
	struct string* dest;
	struct string temp;
	time_t* desttime=NULL;
	size_t i;
	if (wantedtag==UTCTIME) {
	  dest=&temp;
	  desttime=va_arg(args,time_t*);
	} else
	  dest=va_arg(args,struct string*);
	dest->l=0;
	dest->s=0;
	curlen=scan_asn1string(src,maxstack[curmax],&tc,&tt,&tag,&dest->s,&dest->l);
	if (!curlen) { if (optional) break; else goto error; }
	if (application) {
	  if (tc!=APPLICATION) goto error;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=wantedtag)
	    goto error;
	}
	if (wantedtag==BIT_STRING) {	// additional checks for bit strings
	  if (dest->l==0 ||	// length can't be 0 because the format starts with 1 octet that contains the number of unused bits in the last octet
	      ((unsigned char)(dest->s[0])>7) ||	// it's the number of unused bits in an octet, must be [0..7]
	      (dest->l==1 && dest->s[0])) goto error;	// if there is no last octet, there can't be any unused bits in there
	  dest->l=(dest->l-1)*8-dest->s[0];
	  dest->s+=1;
	} else if (wantedtag==PrintableString) {
	  for (i=0; i<dest->l; ++i)	// RFC 2252 section 4.1 production p
	    if (!isalnum(dest->s[i])
		&& dest->s[i]!='"'
		&& dest->s[i]!='('
		&& dest->s[i]!=')'
		&& dest->s[i]!='+'
		&& dest->s[i]!=','
		&& dest->s[i]!='-'
		&& dest->s[i]!='.'
		&& dest->s[i]!='/'
		&& dest->s[i]!=':'
		&& dest->s[i]!='?'
		&& dest->s[i]!=' ') goto error;
	} else if (wantedtag==IA5String) {
	  for (i=0; i<dest->l; ++i)	// IA5String is an ASCII string, which means 0 <= s[i] <= 127
	    if ((unsigned char)(dest->s[i]) > 127) goto error;
	} else if (wantedtag==UTCTIME) {
	  size_t j;
	  struct tm t;
	  memset(&t,0,sizeof(t));
	  /*
		YYMMDDhhmmZ
		YYMMDDhhmm+hh'mm'
		YYMMDDhhmm-hh'mm'
		YYMMDDhhmmssZ
		YYMMDDhhmmss+hh'mm'
		YYMMDDhhmmss-hh'mm'
	   */
	  if (dest->l<11 || dest->l>17) goto error;
	  j=(dest->s[0]-'0')*10+dest->s[1]-'0';
	  t.tm_year=j+(j<70)*100;

	  for (i=0; i<10; ++i)
	    if (!isdigit(dest->s[i])) goto error;
	  j=(dest->s[2]-'0')*10+dest->s[3]-'0';		// is the month plausible?
	  if (j<1 || j>12) goto error;
	  t.tm_mon=j-1;
	  j=(dest->s[4]-'0')*10+dest->s[5]-'0';		// is the day plausible?
	  if (j<1 || j>31) goto error;
	  t.tm_mday=j;
	  j=(dest->s[6]-'0')*10+dest->s[7]-'0';		// is the hour plausible?
	  if (j>23) goto error;
	  t.tm_hour=j;
	  j=(dest->s[8]-'0')*10+dest->s[9]-'0';		// is the minutes plausible?
	  if (j>59) goto error;
	  t.tm_min=j;
	  i=10;
	  if (isdigit(dest->s[10])) {
	    i+=2;
	    j=(dest->s[10]-'0')*10+dest->s[11]-'0';		// is the seconds plausible?
	    if (j>59) goto error;
	    t.tm_sec=j;
	  }
	  *desttime=mktime(&t);
	  if (dest->s[i]=='+' || dest->s[i]=='-') {
	    size_t j;
	    if (dest->l!=15) goto error;
	    for (j=i; j<i+4; ++j)
	      if (!isdigit(dest->s[j])) goto error;
	    j=(dest->s[i]-'0')*10+dest->s[i+1]-'0';		// is the offset minutes plausible?
	    if (j>59) goto error;
	    if (dest->s[i]=='+')
	      *desttime+=j*60;
	    else
	      *desttime-=j*60;
	    j=(dest->s[i+2]-'0')*10+dest->s[i+3]-'0';		// is the offset seconds plausible?
	    if (j>59) goto error;
	    if (dest->s[i]=='+')
	      *desttime+=j;
	    else
	      *desttime-=j;
	  } else if (dest->s[i]!='Z') goto error;
	}
	src+=curlen;
	application=NULL;
	break;
      }
    case 'o':		// o == OID
      {
	struct string* dest=va_arg(args,struct string*);
	curlen=scan_asn1tag(src,maxstack[curmax],&tc,&tt,&tag);
	if (!curlen) { if (optional) break; else goto error; }
	if (application) {
	  if (tc!=APPLICATION) goto error;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=OBJECT_IDENTIFIER)
	    goto error;
	}
	src+=curlen;
	curlen=scan_asn1length(src,maxstack[curmax],&seqlen);
	if (!curlen) goto error;
	src+=curlen;
	dest->s=src;
	dest->l=seqlen;
	src+=seqlen;
	application=NULL;
	break;
      }
    case '*':		// next tag class is APPLICATION instead of UNIVERSAL; write tag to unsigned long*
      {
	application=va_arg(args,unsigned long*);
	break;
      }
    case 'c':		// c = context specific; PRIVATE CONSTRUCTED 0, close with '}'
      desttag=va_arg(args,unsigned long*);
      // fall through
    case '[':		// [ = SET
    case '{':		// { = SEQUENCE
      {
	curlen=scan_asn1tag(src,maxstack[curmax],&tc,&tt,&tag);
	if (!curlen) { if (optional) break; else goto error; }
	if (application) {
	  if (tc!=APPLICATION || tt!=CONSTRUCTED) goto error;
	  *application=tag;
	} else {
	  if (*fmt=='c') {
	    if (tc!=PRIVATE || tt!=CONSTRUCTED)
	      goto error;
	    *desttag=tag;	// gcc -fanalyzer gives a false positive here.
	    // if we get here, *fmt was 'c' and we came in via the "case 'c'"
	    // above which set desttag to something the caller provided.
	  } else {
	    if (tc!=UNIVERSAL || tt!=CONSTRUCTED || tag!=(*fmt=='{'?SEQUENCE_OF:SET_OF))
	      goto error;
	  }
	}
	src+=curlen;
	curlen=scan_asn1length(src,maxstack[curmax],&seqlen);
	if (!curlen || curmax>99) goto error;
	maxstack[++curmax]=src+curlen+seqlen;
	src+=curlen;
	application=NULL;
	break;
      }
    case '!':		// save current src and max-src into struct string*
      // useful for optional parts or CHOICEs
      {
	struct string* dest=va_arg(args,struct string*);
	dest->s=src;
	dest->l=maxstack[curmax]-src;
	break;
      }
    case ']':		// ] = end of SET
    case '}':		// } = end of SEQUENCE
      {
	optional=0;
	if (curmax==0) goto error;
	src=maxstack[curmax];
	--curmax;
	break;
      }
    default:
      goto error;
    }
    ++fmt;
  }
  va_end(args);
  return src-orig;
error:
  va_end(args);
  return 0;
}
