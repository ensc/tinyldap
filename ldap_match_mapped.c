#include "ldap.h"
#include "ldif.h"
#include "byte.h"
#include "str.h"
#include "uint32.h"
#include "case.h"
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

extern char* map;
extern long filelen;
extern uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
extern uint32 dn_ofs,objectClass_ofs;

static int substringmatch(struct Substring* x,const char* attr,int ignorecase) {
  int (*diff)(const void* a, unsigned int len, const void* b);
  if (ignorecase)
    diff=byte_case_diff;
  else
    diff=byte_diff;
  while (x) {
    unsigned int i;
    if (x->s.l>strlen(attr)) return 0;
    switch (x->substrtype) {
    case prefix:
      if (diff(x->s.s,x->s.l,attr)) return 0;
found:
      break;
    case any:
      if (x->s.l>strlen(attr)) return 0;
      for (i=0; i<x->s.l-strlen(attr); ++i) {
	if (!diff(x->s.s,x->s.l,attr+i)) goto found;
      }
      return 0;
    case suffix:
      if (diff(x->s.s,x->s.l,attr+strlen(attr)-x->s.l)) return 0;
    }
    x=x->next;
  }
  return 1;
}

int ldap_match_present(uint32 ofs,uint32 attrofs) {
  uint32 j,k;
  if (attrofs==dn_ofs || attrofs==objectClass_ofs) return 1;
  uint32_unpack(map+ofs,&j);
  for (k=2; k<j; ++k)
    if (uint32_read(map+ofs+k*8)==attrofs)
      return 1;
  return 0;
}

uint32 ldap_find_attr_value(uint32 ofs,uint32 attrofs) {
  uint32 j,k;
  if (attrofs==dn_ofs) return uint32_read(map+ofs+8);
  if (attrofs==objectClass_ofs) return uint32_read(map+ofs+12);
  uint32_unpack(map+ofs,&j);
  for (k=2; k<j; ++k)
    if (uint32_read(map+ofs+k*8)==attrofs)
      return uint32_read(map+ofs+k*8+4);
  return 0;
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
  case PRESENT:
    return ldap_match_present(ofs,f->attrofs);
  case EQUAL:
    {
      uint32 i,j,k;
      uint32_unpack(map+ofs,&j);
//      if (!matchstring(&f->ava.desc,"dn")) {
      if (f->attrofs==dn_ofs) {
	uint32_unpack(map+ofs+8,&k);
	if (f->attrflag&1) {
	  if (!matchcasestring(&f->ava.value,map+k)) return 1;
	} else {
	  if (!matchstring(&f->ava.value,map+k)) return 1;
	}
//      } else if (!matchstring(&f->ava.desc,"objectName")) {
      } else if (f->attrofs==objectClass_ofs) {
	uint32_unpack(map+ofs+12,&k);
	if (f->attrflag&1) {
	  if (!matchcasestring(&f->ava.value,map+k)) return 1;
	} else {
	  if (!matchstring(&f->ava.value,map+k)) return 1;
	}
      }
      for (i=2; i<j; ++i) {
	uint32_unpack(map+ofs+i*8,&k);
//	if (!matchstring(&f->ava.desc,map+k)) {
	if (f->attrofs==k) {
	  uint32_unpack(map+ofs+i*8+4,&k);
	  if (f->attrflag&1) {
	    if (!matchcasestring(&f->ava.value,map+k)) return 1;
	  } else {
	    if (!matchstring(&f->ava.value,map+k)) return 1;
	  }
	}
      }
      return 0;
    }
    break;
  case SUBSTRING:
    {
      uint32 i,j,k;
      uint32_unpack(map+ofs,&j);
//      if (matchstring(&f->ava.desc,"dn")) {
      if (f->attrofs==dn_ofs) {
	uint32_unpack(map+ofs+8,&k);
	if (substringmatch(f->substrings,map+k,f->attrflag&1)) return 1;
//      } else if (matchstring(&f->ava.desc,"objectName")) {
      } else if (f->attrofs==objectClass_ofs) {
	uint32_unpack(map+ofs+12,&k);
	if (substringmatch(f->substrings,map+k,f->attrflag&1)) return 1;
      }
      for (i=2; i<j; ++i) {
	uint32_unpack(map+ofs+i*8,&k);
//	if (!matchstring(&f->ava.desc,map+k)) {
	if (f->attrofs==k) {
	  uint32_unpack(map+ofs+i*8+4,&k);
	  if (substringmatch(f->substrings,map+k,f->attrflag&1))
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

/* return 0 if they didn't match, otherwise return length in b */
static int match(const char* a,int len,const char* b) {
  const char* A=a+len;
  const char* B=b+strlen(b);
  while (len>0 && A>a && B>b) {
    --A; --B; --len;
    while (*A==' ' && A>a) { --A; --len; }
    while (*B==' ' && B>b) --B;
    if (tolower(*A) != tolower(*B))
      return 0;
  }
  return strlen(B);
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
  /* we want "o=foo, o=bar" and "o=FOO,o=baR" to be equal */
  if (sr->baseObject.l && !match(sr->baseObject.s,sr->baseObject.l,map+k)) {
//    puts("fail: not suffix");
    return 0;
  }
  /* it is.  If scope==wholeSubtree, the scope check is also done */
  switch (sr->scope) {
  case wholeSubtree: break;
  case baseObject: if (l==sr->baseObject.l) break; return 0;
  default:
    i=str_chr(map+k,',');
    if (i+2>=l-sr->baseObject.l) break;
    return 0;
  }
  return ldap_matchfilter_mapped(ofs,sr->filter);
}
