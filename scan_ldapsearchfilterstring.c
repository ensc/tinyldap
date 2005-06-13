#include <stdlib.h>
#include "ldap.h"
#include "str.h"

int scan_ldapsearchfilterstring(const char* src,struct Filter** f) {
  char* s=(char*)src;
  if (!(*f=calloc(sizeof(struct Filter),1))) goto error;
  if (*s!='(') goto error;
  switch (*(++s)) {
  case '&': ++s; (*f)->type=AND;
scan_filterlist:
    {
      struct Filter** n;
      s+=scan_ldapsearchfilterstring(s,&(*f)->x);
      n=&(*f)->x->next;
      while (*s!=')') {
	unsigned long l=scan_ldapsearchfilterstring(s,n);
	if (!l) return 0;
	s+=l;
	n=&(*n)->next;
      }
    }
    break;
  case '|': ++s; (*f)->type=OR;
    goto scan_filterlist;
    break;
  case '!':
    (*f)->type=NOT;
    ++s;
    s+=scan_ldapsearchfilterstring(s,&(*f)->x);
    break;
  default:
    (*f)->ava.desc.s=s;
    (*f)->ava.desc.l=str_chr(s,'=')-1;
    s+=(*f)->ava.desc.l+1;
    switch (*(s-1)) {
      case '~': (*f)->type=APPROX; break;
      case '>': (*f)->type=GREATEQUAL; break;
      case '<': (*f)->type=LESSEQUAL; break;
      default:
	++(*f)->ava.desc.l;
	if (*(++s)=='*') {
	  if (*(++s)==')') {
	    (*f)->type=PRESENT;
	    return s-src;
	  }
	 (*f)->type=SUBSTRING;
substring:
	  while (*s!=')') {
	    int i,j;
	    struct Substring* substring=malloc(sizeof(struct Substring));
	    if (!substring) goto error;
	    substring->s.s=s;
	    i=str_chr(s,')');
	    j=str_chr(s,'*');
	    if (i>j) {
	      substring->substrtype=any;
	      s+=substring->s.l=j;
	      ++s;
	    } else {
	      substring->substrtype=suffix;
	      s+=substring->s.l=i;
	    }
	    substring->next=(*f)->substrings;
	    (*f)->substrings=substring;
	  }
	} else {
	  int i,j;
	  i=str_chr(s,')');
	  j=str_chr(s,'*');
	  if (i>j) {
	    struct Substring* substring=malloc(sizeof(struct Substring));
	    if (!substring) goto error;
	    (*f)->type=SUBSTRING;
	    substring->substrtype=prefix;
	    substring->s.s=s;
	    s+=substring->s.l=j;
	    ++s;
	    substring->next=(*f)->substrings;
	    (*f)->substrings=substring;
	    goto substring;
	  } else {
	    (*f)->type=EQUAL;
	  }
	}
    }
    if (*s=='=') ++s;
    (*f)->ava.value.s=s;
    s+=(*f)->ava.value.l=str_chr(s,')');
  }
  return s-src+1;
error:
  return 0;
}
