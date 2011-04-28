#define _FILE_OFFSET_BITS 64
#include <sys/stat.h>
#include <inttypes.h>
#include "asn1.h"
#include "ldap.h"

/* how many attributes do we allow per record? */
#define ATTRIBS 100

struct attribute {
  uint32_t name, value;
};

struct ldaprec {
  uint32_t dn;
  unsigned int n;	/* number of attributes */
  struct attribute a[ATTRIBS];
  struct ldaprec* next;
};

extern uint32_t dn, mail, sn, cn, objectClass;
extern struct ldaprec *first;
extern unsigned long ldifrecords;

int ldif_parse(const char* filename,off_t fromofs,struct stat* ss);

/* return non-zero if the record matches the search request */
int ldap_match(struct ldaprec* r,struct SearchRequest* sr);
int ldap_match_mapped(uint32_t ofs,struct SearchRequest* sr);
int ldap_match_present(uint32_t ofs,uint32_t attrofs);
uint32_t ldap_find_attr_value(uint32_t ofs,uint32_t attrofs);
int ldap_matchfilter_mapped(uint32_t ofs,struct Filter* f);
