
struct attributevalueassertion {
  unsigned char* desc,* value;
  long dlen, vlen;
};

struct attributelist {
  unsigned char* a;
  long alen;
  struct attributelist* next;
};

struct filter {
  enum {
    AND=0, OR=1, NOT=2, EQUAL=3, SUBSTRING=4, GREATEQUAL=5, LESSEQUAL=6, PRESENT=7, APPROX=8, EXTENSIBLE=9
  } type;
  struct attributevalueassertion ava;
  struct attributelist *a;
  enum {
    PREFIX=0, ANY=1, SUFFIX=2
  } substrtype;
  struct filter* x,*next;
};

struct string {
  long l;
  const char* s;
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
  ExtendedRequest=23 /* das ist doch kein Zufall?! */, ExtendedResponse=24
};

void freefilter(struct filter* f);

int scan_ldapmessage(const char* src,const char* max,
		     long* messageid,long* op,long* len);
int scan_ldapbindrequest(const char* src,const char* max,
			 long* version,struct string* name,long* method);
int scan_ldapbindresponse(const char* src,const char* max,
			  long* result,struct string* matcheddn,
			  struct string* errormessage,struct string* referral);

int fmt_ldapmessage(char* dest,long messageid,long op,long len);
int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple);
int fmt_ldapbindresponse(char* dest,long result,char* matcheddn,
			 char* errormessage,char* referral);
