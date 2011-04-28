#include <stdlib.h>
#include <stdarg.h>
#include "asn1.h"

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
  const char* orig=src;
  va_start(args,fmt);
  maxstack[0]=max;
  while (*fmt) {
    switch (*fmt) {
    case '?':		// ? = rest is optional (until end of sequence)
      optional=1;
      break;
    case 'i':		// i = INTEGER
      {
	long* dest=va_arg(args,long*);
	*dest=0;
	curlen=scan_asn1int(src,maxstack[curmax],&tc,&tt,&tag,dest);
	if (application) {
	  if (tc!=APPLICATION) return 0;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=INTEGER)
	    return 0;
	}
	if (!curlen) { if (optional) break; else return 0; }
	src+=curlen;
	application=0;
	break;
      }
    case 'b':		// s = BIT STRING
    case 's':		// s = STRING
      {
	struct string* dest=va_arg(args,struct string*);
	dest->l=0;
	dest->s=0;
	curlen=scan_asn1string(src,maxstack[curmax],&tc,&tt,&tag,&dest->s,&dest->l);
	if (!curlen) { if (optional) break; else return 0; }
	if (application) {
	  if (tc!=APPLICATION) return 0;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=(*fmt=='s'?OCTET_STRING:BIT_STRING))
	    return 0;
	}
	if (*fmt=='b') {	// additional checks for bit strings
	  if (dest->l==0 ||	// length can't be 0 because the format starts with 1 octet that contains the number of unused bits in the last octet
	      ((unsigned char)(dest->s[0])>7) ||	// it's the number of unused bits in an octet, must be [0..7]
	      (dest->l==1 && dest->s[0])) return 0;	// if there is no last octet, there can't be any unused bits in there
	  dest->l=(dest->l-1)*8-dest->s[0];
	  dest->s+=1;
	}
	src+=curlen;
	application=0;
	break;
      }
    case 'o':		// o == OID
      {
	struct oid* dest=va_arg(args,struct oid*);
	curlen=scan_asn1tag(src,maxstack[curmax],&tc,&tt,&tag);
	if (!curlen) { if (optional) break; else return 0; }
	if (application) {
	  if (tc!=APPLICATION) return 0;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=OBJECT_IDENTIFIER)
	    return 0;
	}
	src+=curlen;
	curlen=scan_asn1length(src,maxstack[curmax],&seqlen);
	if (!curlen) return 0;
	src+=curlen;
	curlen=scan_asn1rawoid(src,src+seqlen,dest->a,&dest->l);
	if (!curlen) {
	  if (dest->l && !dest->a) {
	    dest->a=malloc(dest->l*sizeof(dest->a[0]));
	    curlen=scan_asn1rawoid(src,src+seqlen,dest->a,&dest->l);
	  }
	  if (!curlen) return 0;
	}
	src+=curlen;
	application=0;
      }
    case 'a':		// next tag class is APPLICATION instead of UNIVERSAL; write tag to unsigned long*
      {
	application=va_arg(args,unsigned long*);
	break;
      }
    case '{':		// { = SEQUENCE
      {
	curlen=scan_asn1tag(src,maxstack[curmax],&tc,&tt,&tag);
	if (!curlen) { if (optional) break; else return 0; }
	if (application) {
	  if (tc!=APPLICATION) return 0;
	  *application=tag;
	} else {
	  if (tc!=UNIVERSAL || tt!=CONSTRUCTED || tag!=SEQUENCE_OF)
	    return 0;
	}
	src+=curlen;
	curlen=scan_asn1length(src,maxstack[curmax],&seqlen);
	if (!curlen) return 0;
	if (curmax>99) return 0;
	maxstack[++curmax]=src+curlen+seqlen;
	src+=curlen;
	application=0;
	break;
      }
    case '!':		// save current max-src into size_t
      // useful for ldap, where you have an application sequence
      // and the tag defines which encoding you have inside the
      // sequence, so you can't put it in the format string.
      // you still need to know the length so you can call this function
      // again on the rest of the data.
      {
	size_t* dest=va_arg(args,size_t*);
	*dest=maxstack[curmax]-src;
	break;
      }
    case '}':		// } = end of SEQUENCE
      {
	optional=0;
	if (curmax==0) return 0;
	--curmax;
	break;
      }
    default:
      return 0;
    }
    ++fmt;
  }
  va_end(args);
  return src-orig;
}
