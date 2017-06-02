#include <libowfat/fmt.h>
#include <libowfat/byte.h>
#include <libowfat/str.h>
#include "ldap.h"

size_t fmt_escapesearchfilterstring(char* dest,const char* s,size_t len) {
  size_t i,j;
  for (i=j=0; i<len; ++i,++j) {
    switch (s[i]) {
    case '*': case '\\': case '(': case ')': case 0:	// RFC4515
      if (dest) {
	dest[j]='\\';
	dest[j+1]=fmt_tohex((unsigned char)(s[i])>>4);
	dest[j+2]=fmt_tohex(s[i]&0xf);
      }
      j+=2;
      break;
    default:
      if (dest)
	dest[j]=s[i];
    }
  }
  return j;
}

size_t fmt_ldapsearchfilterstring(char* dest,const struct Filter* f) {
  size_t len;
  len = fmt_str(dest,"(");
  do {
    switch (f->type) {
    case AND: case OR: case NOT:
      if (dest) dest[len]="&|!"[f->type];
      ++len;
      len += fmt_ldapsearchfilterstring(dest?dest+len:0,f->x);
      break;
    case EQUAL: case GREATEQUAL: case LESSEQUAL: case APPROX:
      if (dest) {
	len += fmt_escapesearchfilterstring(dest+len,f->ava.desc.s,f->ava.desc.l);
//	byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
//	len += f->ava.desc.l;
	if (f->type!=EQUAL) {
	  dest[len]="><~"[f->type-GREATEQUAL];
	  ++len;
	}
	dest[len]='='; ++len;
	len += fmt_escapesearchfilterstring(dest+len,f->ava.value.s,f->ava.value.l);
//	byte_copy(dest+len,f->ava.value.l,f->ava.value.s);
//	len += f->ava.value.l;
      } else
	len += fmt_escapesearchfilterstring(NULL,f->ava.desc.s,f->ava.desc.l) +
	       fmt_escapesearchfilterstring(NULL,f->ava.value.s,f->ava.value.l) +
	       1 + (f->type>EQUAL);
      break;
    case SUBSTRING:
      {
	struct Substring* x=f->substrings;
	while (x) {
	  if (dest) {
	    len += fmt_escapesearchfilterstring(dest+len,f->ava.desc.s,f->ava.desc.l);
//	    byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
//	    len += f->ava.desc.l;
	    dest[len]='='; ++len;
	    if (x->substrtype != prefix) {
	      dest[len]='*'; ++len;
	    }
	    len += fmt_escapesearchfilterstring(dest+len,x->s.s,x->s.l);
//	    byte_copy(dest+len,x->s.l,x->s.s);
//	    len += x->s.l;
	    if (x->substrtype != suffix) {
	      dest[len]='*'; ++len;
	    }
	    if (x->next) {
	      dest[len]=')';
	      dest[len+1]='(';
	      len+=2;
	    }
	  } else
	    len += f->ava.desc.l + 1 + x->s.l + 1 + (x->substrtype==any) + (x->next?2:0);
	  x=x->next;
	}
      }
      break;
    case PRESENT:
      if (dest) {
	len += fmt_escapesearchfilterstring(dest+len,f->ava.desc.s,f->ava.desc.l);
//	byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
	dest[len]='=';
	dest[len+1]='*';
      } else
	len += fmt_escapesearchfilterstring(NULL,f->ava.desc.s,f->ava.desc.l);
      len += 2;
      break;
    default:
      return -1;
    }
    f=f->next;
    if (f) {
      if (dest) {
	dest[len]=')';
	dest[len+1]='(';
      }
      len+=2;
    }
  } while (f);
  if (dest) dest[len]=')';
  return len+1;
}
