#ifndef _LDAP_H
#define _LDAP_H

struct string {
  long l;
  const char* s;
};

struct AttributeValueAssertion {
  struct string desc, value;
};

struct AttributeDescriptionList {
  struct string a;
  struct AttributeDescriptionList *next;
};

struct PartialAttributeList {
  struct string type;
  struct AttributeDescriptionList* values;
  struct PartialAttributeList* next;
};

struct Substring {
  enum { prefix=0, any=1, suffix=2 } substrtype;
  struct string s;
  struct Substring* next;
};

struct Filter {
  enum {
    AND=0, OR=1, NOT=2, EQUAL=3, SUBSTRING=4, GREATEQUAL=5, LESSEQUAL=6, PRESENT=7, APPROX=8, EXTENSIBLE=9
  } type;
  struct AttributeValueAssertion ava;
  struct Substring* substrings;
  struct AttributeDescriptionList *a;
  struct Filter* x,*next;
};

struct SearchRequest {
  struct string baseObject;
  enum { baseObject=0, singleLevel=1, wholeSubtree=2 } scope;
  enum {
    neverDerefAliases=0,
    derefInSearching=1,
    derefFindingBaseObj=2,
    derefAlways=3
  } derefAliases;
  unsigned long sizeLimit, timeLimit, typesOnly;
  struct Filter* filter;
    /* really an AttributeDescriptionList, but the types are equivalent: */
  struct AttributeDescriptionList* attributes;
};

struct SearchResultEntry {
  struct string objectName;
  struct PartialAttributeList* attributes;
};

enum ldapops {
  BindRequest=0, BindResponse=1,
  UnbindRequest=2,
  SearchRequest=3, SearchResultEntry=4, SearchResultDone=5,
  ModifyRequest=6, ModifyResponse=7,
  AddRequest=8, AddResponse=9,
  DelRequest=10, DelResponse=11,
  ModifyDNRequest=12, ModifyDNResponse=13,
  CompareRequest=14, CompareResponse=15,
  AbandonRequest=16,
  ExtendedRequest=23 /* coincidence?  I think not. */,
  ExtendedResponse=24
};

void freefilter(struct Filter* f);
void freeava(struct AttributeDescriptionList* a);
void freepal(struct PartialAttributeList* a);

int scan_ldapstring(const char* src,const char* max,struct string* s);
int scan_ldapmessage(const char* src,const char* max,
		     long* messageid,long* op,long* len);
int scan_ldapbindrequest(const char* src,const char* max,
			 long* version,struct string* name,long* method);
int scan_ldapbindresponse(const char* src,const char* max,
			  long* result,struct string* matcheddn,
			  struct string* errormessage,struct string* referral);
int scan_ldapava(const char* src,const char* max,struct AttributeValueAssertion* a);
int scan_ldapsearchfilter(const char* src,const char* max,struct Filter** f);
int scan_ldapsearchrequest(const char* src,const char* max,struct SearchRequest* s);
int scan_ldapsearchresultentry(const char* src,const char* max,struct SearchResultEntry* sre);
int scan_ldapresult(const char* src,const char* max,long* result,
		    struct string* matcheddn,struct string* errormessage,
		    struct string* referral);

int fmt_ldapstring(char* dest,struct string* s);
int fmt_ldapmessage(char* dest,long messageid,long op,long len);
int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple);
int fmt_ldapbindresponse(char* dest,long result,char* matcheddn,
			 char* errormessage,char* referral);
int fmt_ldapsearchfilter(char* dest,struct Filter* f);
int fmt_ldapsearchrequest(char* dest,struct SearchRequest* s);
int fmt_ldapsearchresultentry(char* dest,struct SearchResultEntry* sre);
int fmt_ldapsearchresultdone(char* dest,long result,char* matcheddn,char* errormessage,char* referral);

#endif
