#include <unistd.h>
#include <stdio.h>
#include "mmap.h"
#include "asn1.h"
#include "ldap.h"

void printava(struct AttributeValueAssertion* a,const char* rel) {
  printf("[%.*s %s %.*s]",(int)a->desc.l,a->desc.s,rel,(int)a->value.l,a->value.s);
}

void printal(struct AttributeDescriptionList* a) {
  while (a) {
    printf("%.*s",(int)a->a.l,a->a.s);
    a=a->next;
    if (a) printf(",");
  }
  printf("\n");
}

void printfilter(struct Filter* f) {
  switch (f->type) {
  case AND:
    printf("&(");
mergesub:
    printfilter(f->x);
    printf(")");
    break;
  case OR:
    printf("|(");
    goto mergesub;
    break;
  case NOT:
    printf("!(");
    goto mergesub;
  case EQUAL:
    printava(&f->ava,"==");
    break;
  case SUBSTRING:
    printava(&f->ava,"\\in");
    break;
  case GREATEQUAL:
    printava(&f->ava,">=");
    break;
  case LESSEQUAL:
    printava(&f->ava,"<=");
    break;
  case PRESENT:
    printava(&f->ava,"\\exist");
    break;
  case APPROX:
    printava(&f->ava,"\\approx");
    break;
  case EXTENSIBLE:
    printf("[extensible]");
    break;
  }
  if (f->next) {
    printf(",");
    printfilter(f->next);
  }
}

int main(int argc,char* argv[]) {
#if 1
  unsigned long size;
//  char* ldapsequence=mmap_read("req",&size);
  char* ldapsequence=mmap_read(argc>1?argv[1]:"capture/127.000.000.001.32779-127.000.000.001.00389",&size);
  long messageid, op, len;
  int res,done=0;
  while (done<size) {
    printf("scan_ldapmessage: %d\n",res=scan_ldapmessage(ldapsequence+done,ldapsequence+size,&messageid,&op,&len));
    if (!res) { puts("punt!"); break; }
    printf("message id %lu, op %lu, len %lu\n",messageid,op,len);
    switch (op) {
    case BindRequest:
      puts("  >> BindRequest <<");
      {
	long version,method;
	struct string name;
	int tmp;
	printf("scan_ldapbindrequest: %d\n",tmp=scan_ldapbindrequest(ldapsequence+done+res,ldapsequence+done+res+len,&version,&name,&method));
	printf("version %lu, name \"%.*s\", method %lu\n",version,(int)name.l,name.s,method);
	if (method==0) {
	  if (scan_ldapstring(ldapsequence+done+res+tmp,ldapsequence+size,&name))
	    printf("simple \"%.*s\"\n",(int)name.l,name.s);
	  else
	    puts("method 0 but couldn't parse simple");
	} else
	  puts("unknown method!");
	break;
      }
    case SearchRequest:
      puts("  >> SearchRequest <<");
      {
	struct SearchRequest br;
	int tmp;
	printf("scan_ldapsearchrequest %d\n",tmp=scan_ldapsearchrequest(ldapsequence+done+res,ldapsequence+size,&br));
	if (tmp) {
	  printf("baseObject: \"%.*s\"\n",(int)br.baseObject.l,br.baseObject.s);
	  printfilter(br.filter); printf("\n");
	}
	printal(br.attributes);
	break;
      }
    case UnbindRequest:
      puts("  >> UnbindRequest <<");
      break;
    default:
      puts("  >> unklar << ;)");
    }
    done+=len+res;
  }
#endif
#if 0
  char buf[1024];
  enum asn1_tagtype tt;
  enum asn1_tagclass tc;
  long tag,len;
  int res;
  const char* c;
  printf("%d\n",res=fmt_asn1int(buf,UNIVERSAL,PRIMITIVE,INTEGER,0x01020304));
  printf("%d\n",scan_asn1int(buf,buf+res,&tc,&tt,&tag,&len));
  printf("got %lx\n",len);
  printf("%d\n",res=fmt_asn1string(buf,UNIVERSAL,PRIMITIVE,OCTET_STRING,"fnord",5));
  printf("%d\n",scan_asn1string(buf,buf+res,&tc,&tt,&tag,&c,&len));
  printf("got %.*s\n",(int)len,c);
#endif
  return 0;
}
