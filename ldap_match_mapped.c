#include "ldap.h"
#include "ldif.h"
#include "byte.h"
#include "str.h"
#include "uint32.h"
#include <unistd.h>
#include <stdio.h>

extern char* map;
extern long filelen;
extern uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;

static int substringmatch(struct Substring* x,const char* attr) {
  while (x) {
    unsigned int i;
    if (x->s.l>strlen(attr)) return 0;
    switch (x->substrtype) {
    case prefix:
      if (byte_diff(x->s.s,x->s.l,attr)) return 0;
found:
      break;
    case any:
      for (i=0; i<x->s.l-strlen(attr); ++i)
	if (byte_equal(x->s.s+i,x->s.l,attr)) goto found;
      return 0;
    case suffix:
      if (byte_diff(x->s.s+x->s.l-strlen(attr),x->s.l,attr)) return 0;
    }
    x=x->next;
  }
  return 1;
}

/* return non-zero if the record matches the search filter */
int ldap_matchfilter_mapped(uint32 ofs,struct Filter* f) {
  struct Filter* y=f->x;
  if (!f) return 1;
  switch (f->type) {
  case AND:
    while (y) {
      if (!ldap_matchfilter_mapped(ofs,y)) return 0;
      y=y->next;
    }
    return 1;
  case OR:
    while (y) {
      if (ldap_matchfilter_mapped(ofs,y)) return 1;
      y=y->next;
    }
    return 0;
  case NOT:
    return !ldap_matchfilter_mapped(ofs,y);
  case EQUAL:
    {
      uint32 i=2,j,k;
      uint32_unpack(map+ofs,&j);
      if (!matchstring(&f->ava.desc,"dn")) {
	uint32_unpack(map+ofs+8,&k);
	if (!matchstring(&f->ava.value,map+k)) return 1;
      } else if (!matchstring(&f->ava.desc,"objectName")) {
	uint32_unpack(map+ofs+12,&k);
	if (!matchstring(&f->ava.value,map+k)) return 1;
      }
      for (i=2; i<j; ++i) {
	uint32_unpack(map+ofs+i*8,&k);
	if (!matchstring(&f->ava.desc,map+k)) {
	  uint32_unpack(map+ofs+i*8+4,&k);
	  if (!matchstring(&f->ava.value,map+k))
	    return 1;
	}
      }
      return 0;
    }
    break;
  case SUBSTRING:
    {
      uint32 i=2,j,k;
      uint32_unpack(map+ofs,&j);
      if (matchstring(&f->ava.desc,"dn")) {
	uint32_unpack(map+ofs+8,&k);
	if (substringmatch(f->substrings,map+k)) return 1;
      } else if (matchstring(&f->ava.desc,"objectName")) {
	uint32_unpack(map+ofs+12,&k);
	if (substringmatch(f->substrings,map+k)) return 1;
      }
      for (i=2; i<j; ++i) {
	uint32_unpack(map+ofs+i*8,&k);
	if (!matchstring(&f->ava.desc,map+k)) {
	  uint32_unpack(map+ofs+i*8+4,&k);
	  if (substringmatch(f->substrings,map+k))
	    return 1;
	}
      }
      return 0;
    }
    break;
  default:
    write(2,"unsupported query type\n",4);
    return 0;
  }
  return 1;
}

/* return non-zero if the record matches the search request */
int ldap_match_mapped(uint32 ofs,struct SearchRequest* sr) {
  unsigned int l,i;
  uint32 k;
  uint32_unpack(map+ofs+8,&k);
  l=strlen(map+k);
  /* first see if baseObject is a suffix of dn */
  if (sr->baseObject.l>l) {
//    puts("fail: baseObject longer than dn");
    return 0;
  }
  if (!byte_equal(sr->baseObject.s,sr->baseObject.l,map+k+l-sr->baseObject.l)) {
//    puts("fail: not suffix");
    return 0;
  }
  /* it is.  If scope==wholeSubtree, the scope check is also done */
  switch (sr->scope) {
  case wholeSubtree: break;
  case baseObject: if (l==sr->baseObject.l) break; return 0;
  default:
    i=str_chr(map+k,',');
    if (i+2>=sr->baseObject.l-l) break;
    return 0;
  }
  return ldap_matchfilter_mapped(ofs,sr->filter);
}
