#include <unistd.h>
#include "ldap.h"
#include <libowfat/byte.h>
#include <libowfat/case.h>
#include <ctype.h>

static int matchcasestr(struct string* a,struct string* b) {
  unsigned long l=a->l;
  unsigned long r;
  if (b->l<l) l=b->l;
  if ((r=case_diffb(a->s,l,b->s))) return r;
  if (a->l>l) return 1;
  if (b->l>l) return -1;
  return 0;
}

static int matchstr(struct string* a,struct string* b) {
  unsigned long l=a->l;
  unsigned long r;
  if (b->l<l) l=b->l;
  if ((r=byte_diff(a->s,l,b->s))) return r;
  if (a->l>l) return 1;
  if (b->l>l) return -1;
  return 0;
}

static int matchstr_sre(struct Filter* f,struct string* s) {
  int r;
  if (f->attrflag&1)
    r=matchcasestr(&f->ava.value,s);
  else
    r=matchstr(&f->ava.value,s);
  if (f->type==EQUAL) return (r==0);
  if (f->type==LESSEQUAL) return (r>0);
  return (r<0);
}

static int ldap_match_present_sre(struct SearchResultEntry* sre,struct string* s) {
  struct PartialAttributeList* p;
  for (p=sre->attributes; p; p=p->next) {
    int r;
    if ((r=matchstr(&p->type,s))) return r;
  }
  return 0;
}

static int substrmatch(struct Substring* x,struct string* s,int ignorecase) {
  int (*diff)(const void* a, size_t len, const void* b);
  if (ignorecase)
    diff=case_diffb;
  else
    diff=byte_diff;
  while (x) {
    unsigned long i;
    if (x->s.l>s->l) return 0;
    switch (x->substrtype) {
    case prefix:
      if (diff(x->s.s,x->s.l,s->s)) return 0;
found:
      break;
    case any:
      if (s->l<x->s.l) return 0;
      for (i=0; i<=s->l-x->s.l; ++i)
	if (!diff(x->s.s,x->s.l,s->s+i))
	  goto found;
      return 0;
    case suffix:
      if (diff(x->s.s,x->s.l,s->s+s->l-x->s.l)) return 0;
    }
    x=x->next;
  }
  return 1;
}

extern uint32_t dn_ofs;

int ldap_matchfilter_sre(struct SearchResultEntry* sre,struct Filter* f) {
  struct PartialAttributeList* p;
  struct Filter* y=f->x;
  if (!f) return 1;
  switch (f->type) {
  case AND:
    while (y) {
      if (!ldap_matchfilter_sre(sre,y)) return 0;
      y=y->next;
    }
    return 1;
  case OR:
    while (y) {
      if (ldap_matchfilter_sre(sre,y)) return 1;
      y=y->next;
    }
    return 0;
  case NOT:
    return !ldap_matchfilter_sre(sre,y);
  case PRESENT:
    return ldap_match_present_sre(sre,&f->ava.desc);
  case EQUAL:
  case LESSEQUAL:
  case GREATEQUAL:
    if (f->attrofs==dn_ofs)
      return matchstr_sre(f,&sre->objectName);
    for (p=sre->attributes; p; p=p->next) {
      int r;
      struct AttributeDescriptionList* a;
      if (matchstr(&f->ava.desc,&p->type)) {
	for (a=p->values; a; a=a->next)
	  if ((r=matchstr_sre(f,&a->a))) return r;
	return 0;
      }
    }
    return 0;
  case SUBSTRING:
    if (f->attrofs==dn_ofs)
      return substrmatch(f->substrings,&sre->objectName,f->attrflag&1);
    for (p=sre->attributes; p; p=p->next) {
      if (matchstr(&f->ava.desc,&p->type)) {
	struct AttributeDescriptionList* a;
	int r;
	for (a=p->values; a; a=a->next)
	  if ((r=substrmatch(f->substrings,&a->a,f->attrflag&1))) return r;
	return 0;
      }
    }
    return 0;
  default:
    write(2,"unsupported query type\n",23);
    return 0;
  }
  return 1;
}

/* return 0 if they didn't match, otherwise return length in b */
static int match(const char* a,int len,const char* b,int blen) {
  const char* A=a+len;
  const char* B=b+blen;
  while (len>0 && A>a && B>b) {
    --A; --B; --len;
    while (*A==' ' && A>a) { --A; --len; }
    while (*B==' ' && B>b) --B;
    if (tolower(*A) != tolower(*B))
      return 0;
  }
  return b+blen-B;
}

int ldap_match_sre(struct SearchResultEntry* sre,struct SearchRequest* sr) {
  unsigned long i;
  if (sr->baseObject.l>sre->objectName.l)
    /* baseObject is longer than dn */
    return 0;
  if (sr->baseObject.l && !match(sr->baseObject.s,sr->baseObject.l,sre->objectName.s,sre->objectName.l))
    /* baseObject is not a suffix of dn */
    return 0;
  switch (sr->scope) {
  case wholeSubtree: break;
  case baseObject: if (sre->objectName.l==sr->baseObject.l) break; return 0;
  default:
    for (i=0; i<sre->objectName.l; ++i)
      if (sre->objectName.s[i]==',')
	break;
    if (i+2>=sre->objectName.l-sr->baseObject.l) break;
    return 0;
  }
  return ldap_matchfilter_sre(sre,sr->filter);
}
