#include "ldap.h"
#include "ldif.h"
#include "byte.h"
#include "str.h"
#include <unistd.h>
#include <stdio.h>

/* look up value of an attribute for an LDIF record.
 * Return NULL if not found */
static const char* findattr(struct ldaprec* f,struct string* name) {
  int i;
  if (!matchstring(name,"dn")) return f->dn;
  for (i=0; i<ATTRIBS; ++i)
    if (!matchstring(name,f->a[i].name))
      return f->a[i].value;
  return 0;
}

/* return non-zero if the record matches the search filter */
int ldap_matchfilter(struct ldaprec* s,struct Filter* f) {
  struct Filter* y=f->x;
  if (!f) return 1;
  switch (f->type) {
  case AND:
    while (y) {
      if (!ldap_matchfilter(s,y)) return 0;
      y=y->next;
    }
    return 1;
  case OR:
    while (y) {
      if (ldap_matchfilter(s,y)) return 1;
      y=y->next;
    }
    return 0;
  case NOT:
    return !ldap_matchfilter(s,y);
  case EQUAL:
//    printf("  -> \"%s\" vs. \"%.*s\"\n",findattr(s,&f->ava.desc),f->ava.value.l,f->ava.value.s);
    if (matchstring(&f->ava.value,findattr(s,&f->ava.desc))) return 0;
//    puts("yes!!!");
    break;
  case SUBSTRING:
    {
      struct Substring* x=f->substrings;
      const char* attr=findattr(s,&f->ava.desc);
      if (!attr) return 0;
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
    if (f->substrings->substrtype!=prefix) return 0;
  default:
    write(2,"foo\n",4);
    return 0;
  }
  return 1;
}

/* return non-zero if the record matches the search request */
int ldap_match(struct ldaprec* r,struct SearchRequest* sr) {
  unsigned int l=strlen(r->dn);
  unsigned int i;
//  printf("comparing \"%s\" and \"%.*s\"\n",r->dn,(int)sr->baseObject.l,sr->baseObject.s);
  /* first see if baseObject is a suffix of dn */
  if (sr->baseObject.l>l) {
//    puts("fail: baseObject longer than dn");
    return 0;
  }
  if (!byte_equal(sr->baseObject.s,sr->baseObject.l,r->dn+l-sr->baseObject.l)) {
//    puts("fail: not suffix");
    return 0;
  }
  /* it is.  If scope==wholeSubtree, the scope check is also done */
  switch (sr->scope) {
  case wholeSubtree: break;
  case baseObject: if (l==sr->baseObject.l) break; return 0;
  default:
    i=str_chr(r->dn,',');
    if (i+2>=sr->baseObject.l-l) break;
    return 0;
  }
  return ldap_matchfilter(r,sr->filter);
}
