#include <stdlib.h>
#include "asn1.h"
#include "ldap.h"

#if 0
        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
                object          LDAPDN,
                modification    SEQUENCE OF SEQUENCE {
                        operation       ENUMERATED {
                                                add     (0),
                                                delete  (1),
                                                replace (2) },
                        modification    AttributeTypeAndValues } }

        AttributeTypeAndValues ::= SEQUENCE {
                type    AttributeDescription,
                vals    SET OF AttributeValue }
#endif

unsigned int scan_ldapmodifyrequest(const char* src,const char* max,struct ModifyRequest* m) {
  unsigned int res,tmp;
  long oslen; /* outer sequence length */
  struct Modification* last=0;
  m->m.next=0;
  if (!(res=scan_ldapstring(src,max,&m->object))) goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen))) goto error;
  res+=tmp;
  if (src+res+oslen>max) goto error;
  max=src+res+oslen;
  if (src+res>=max) goto error;		/* need at least one record */
  do {
    long islen, etmp;
    if (last) {
      struct Modification* cur;
      if (!(cur=malloc(sizeof(struct Modification)))) goto error;
      last->next=cur; last=cur;
    } else
      last=&m->m;
    last->next=0;
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen))) goto error;
    res+=tmp;
    if (!(tmp=scan_asn1ENUMERATED(src+res,max,&etmp))) goto error;
    if (etmp>2) goto error; last->operation=etmp; res+=tmp;
    {
      long iislen;	/* urgh, _three_ levels of indirection */
      const char* imax;
      if (!(tmp=scan_asn1SEQUENCE(src+res,max,&iislen))) goto error;
      res+=tmp;
      imax=src+res+iislen;
      if (imax>max) goto error;
      if (!(tmp=scan_ldapstring(src+res,imax,&last->AttributeDescription))) goto error;
      res+=tmp;
      {
	long iiislen;	/* waah, _four_ levels of indirection!  It doesn't get more inefficient than this */
	const char* iimax;
	struct AttributeDescriptionList* ilast=0;
	if (!(tmp=scan_asn1SET(src+res,max,&iiislen))) goto error;
	res+=tmp;
	iimax=src+res+iiislen;
	if (src+res+iiislen!=imax) goto error;
	while (src+res<iimax) {
	  if (ilast) {
	    struct AttributeDescriptionList* x;
	    if (!(x=malloc(sizeof(struct AttributeDescriptionList)))) goto error;
	    x->next=ilast; ilast=x;
	  } else
	    ilast=&last->vals;
	  if (!(tmp=scan_ldapstring(src+res,imax,&ilast->a))) goto error;
	  res+=tmp;
	}
      }
    }
    break;
  } while (src+res<max);
  return res;
error:
  free_ldapmodifyrequest(m);
  return 0;
}

static void free_mod(struct Modification* m) {
  while (m) {
    struct Modification* tmp=m->next;
    free(m);
    m=tmp;
  }
}

void free_ldapmodifyrequest(struct ModifyRequest* m) {
  free_ldapadl(m->m.vals.next);
  free_mod(m->m.next);
}
