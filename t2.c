#include <unistd.h>
#include <stdio.h>
#include "mmap.h"
#include "asn1.h"
#include "ldap.h"

int main(int argc,char* argv[]) {
#if 0
  unsigned long size;
//  char* ldapsequence=mmap_read("req",&size);
  char* ldapsequence=mmap_read(argc>1?argv[1]:"capture/127.000.000.001.32779-127.000.000.001.00389",&size);
  long messageid, op, len;
  int res;
  printf("%d\n",res=scan_ldapmessage(ldapsequence,ldapsequence+size,&messageid,&op,&len));
  printf("message id %lu, op %lu, len %lu\n",messageid,op,len);
  if (op==0) {
    long version,namelen,method;
    const char* name;
    printf("%d\n",res=scan_ldapbindrequest(ldapsequence+res,ldapsequence+size,&version,&name,&namelen,&method));
    printf("version %lu, name \"%*s\", method %lu\n",version,namelen,name,method);
    if (method==0) {
      printf("%d\n",scan_asn1STRING(ldapsequence+res,ldapsequence+size,&name,&namelen));
      printf("simple \"%*s\"\n",namelen,name);
    }
  }
#else
  char buf[1024];
  int s=100;
  int len=fmt_ldapbindrequest(buf+s,3,"","");
  int hlen=fmt_ldapmessage(0,1,0,len);
  fmt_ldapmessage(buf+s-hlen,1,0,len);
  write(1,buf+s-hlen,len+hlen);
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
  printf("got %*s\n",(int)len,c);
#endif
  return 0;
}
