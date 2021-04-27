#include <stdlib.h>
#include "ldap.h"
#include <libowfat/buffer.h>
#include <libowfat/byte.h>

#if 0
        AddRequest ::= [APPLICATION 8] SEQUENCE {
                entry           LDAPDN,
                attributes      SEQUENCE OF SEQUENCE {
                        type            AttributeDescription,
                        vals            SET OF AttributeValue } }

        AttributeList ::= SEQUENCE OF SEQUENCE {
                type    AttributeDescription,
                vals    SET OF AttributeValue }
#endif

size_t scan_ldapaddrequest(const char* src,const char* max,struct AddRequest* a) {
  size_t res,tmp,oslen;
  struct Addition* last=0;
  byte_zero(a,sizeof(*a));
  if (!(res=scan_ldapstring(src,max,&a->entry))) goto error;
  if (!(tmp=scan_asn1SEQUENCE(src+res,max,&oslen))) goto error;
  res+=tmp;
  if (src+res+oslen>max) goto error;
  max=src+res+oslen;
  if (src+res>=max) goto error;		/* need at least one record */
  do {
    size_t islen;
    if (last) {
      struct Addition* cur;
      if (!(cur=malloc(sizeof(struct Addition))))
        goto error;
      last->next=cur;
      last=cur;
    } else {
      last=&a->a;
    }
    byte_zero(last, sizeof(*last));
    if (!(tmp=scan_asn1SEQUENCE(src+res,max,&islen)))
      goto error;
    res+=tmp;
    /* scan AttributeDescription: */
    if (!(tmp=scan_ldapstring(src+res,max,&last->AttributeDescription)))
      goto error;
    res+=tmp;

    /* scan set of AttributeValue: */
    {
      size_t set_len;
      const char* set_max;
      struct AttributeDescriptionList* ilast=0;
      if (!(tmp=scan_asn1SET(src+res,max,&set_len))) {
        goto error;
      }
      res+=tmp;
      set_max=src+res+set_len;
      if (src+res+set_len!=set_max) {
        goto error;
      }
      while (src+res<set_max) {
        if (ilast) {
          struct AttributeDescriptionList* x;
          if (!(x=malloc(sizeof(struct AttributeDescriptionList)))) goto error;
          ilast->next=x;
          ilast = ilast->next;
        } else {
          ilast=&last->vals;
        }
	ilast->next=0;
        if (!(tmp=scan_ldapstring(src+res,max,&ilast->a)))
          goto error;
        res+=tmp;
      }
    }
  } while (src+res<max);
//  buffer_putsflush(buffer_2,"done with scan_ldapaddrequest!\n");
  return res;
error:
  free_ldapaddrequest(a);
  return 0;
}

static void free_add(struct Addition * a) {
  while (a) {
    struct Addition * tmp = a->next;
    free(a);
    a = tmp;
  }
}

void free_ldapaddrequest(struct AddRequest * a) {
  free_ldapadl(a->a.vals.next);
  free_add(a->a.next);
}
