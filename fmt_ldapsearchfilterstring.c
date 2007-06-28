#include "fmt.h"
#include "byte.h"
#include "str.h"
#include "ldap.h"

size_t fmt_ldapsearchfilterstring(char* dest,struct Filter* f) {
  size_t len;
  len = fmt_str(dest,"(");
  switch (f->type) {
  case AND: case OR: case NOT:
    if (dest) dest[len]="&|!"[f->type];
    ++len;
    len += fmt_ldapsearchfilterstring(dest?dest+len:0,f->x);
    break;
  case EQUAL: case GREATEQUAL: case LESSEQUAL: case APPROX:
    if (dest) {
      byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
      len += f->ava.desc.l;
      if (f->type!=EQUAL) {
	dest[len]="><~"[f->type-GREATEQUAL];
	++len;
      }
      dest[len]='='; ++len;
      byte_copy(dest+len,f->ava.value.l,f->ava.value.s);
      len += f->ava.value.l;
    } else
      len += f->ava.desc.l + f->ava.value.l + 1 + (f->type>EQUAL);
    break;
  case SUBSTRING:
    {
      struct Substring* x=f->substrings;
      while (x) {
	if (dest) {
	  byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
	  len += f->ava.desc.l;
	  dest[len]='='; ++len;
	  if (x->substrtype != prefix) {
	    dest[len]='*'; ++len;
	  }
	  byte_copy(dest+len,x->s.l,x->s.s);
	  len += x->s.l;
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
      byte_copy(dest+len,f->ava.desc.l,f->ava.desc.s);
      dest[len+f->ava.desc.l]='=';
      dest[len+f->ava.desc.l+1]='*';
    }
    len += f->ava.desc.l+2;
    break;
  default:
    return -1;
  }
  if (dest) dest[len]=')';
  return len+1;
}
