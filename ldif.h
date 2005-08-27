#include "uint32.h"
#include <ldap.h>

/* how many attributes do we allow per record? */
#define ATTRIBS 100

struct attribute {
  uint32 name, value;
};

struct ldaprec {
  uint32 dn;
  int n;	/* number of attributes */
  struct attribute a[ATTRIBS];
  struct ldaprec* next;
};

extern uint32 dn, mail, sn, cn, objectClass;
extern struct ldaprec *first;
extern unsigned long ldifrecords;

int ldif_parse(const char* filename);

/* return non-zero if the record matches the search request */
int ldap_match(struct ldaprec* r,struct SearchRequest* sr);
int ldap_match_mapped(uint32 ofs,struct SearchRequest* sr);
int ldap_match_present(uint32 ofs,uint32 attrofs);
uint32 ldap_find_attr_value(uint32 ofs,uint32 attrofs);
int ldap_matchfilter_mapped(uint32 ofs,struct Filter* f);
