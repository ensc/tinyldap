#include "uint32.h"
#include <ldap.h>

/* how many attributes do we allow per record? */
#define ATTRIBS 8

struct attribute {
  long name, value;
};

struct ldaprec {
  long dn, mail, sn, cn;	/* most often encountered records */
  int n;	/* number of attributes */
  struct attribute a[ATTRIBS];
  struct ldaprec* next;
};

extern long dn, mail, sn, cn, objectClass;
extern struct ldaprec *first;
extern unsigned long ldifrecords;

int ldif_parse(const char* filename);

/* return non-zero if the record matches the search request */
int ldap_match(struct ldaprec* r,struct SearchRequest* sr);
int ldap_match_mapped(uint32 ofs,struct SearchRequest* sr);
