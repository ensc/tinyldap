#include "ldap.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

int main(int argc,char* argv[]) {
  char buf[1000];
  char* max;
  char* want;
  ssize_t i;
  int expecterror=0;

  for (;;) {
    int c=getopt(argc,argv,"e");
    if (c==-1) break;
    switch (c) {
    case 'e': expecterror=1; break;
    }
  }

  i=read(0,buf,0xe);
  if (i!=0xe) {
    puts("short read");
    return 1;
  }
  max=buf+i;
  size_t res,Len;
  unsigned long messageid,op,result;
  if (buf[0]!='0' || (res=scan_asn1length(buf+1,buf+1000,&Len))==0) {
    puts("parse error");
    return 1;
  }
  if (Len>1000)  {
    puts("response > 1000 bytes");
    return 1;
  }
  want=buf+res+1+Len;
  while (max<want) {
    i=read(0,max,want-max);
    if (i!=want-max) {
      puts("read error");
      return 1;
    }
    max+=i;
  }
  res=scan_ldapmessage(buf,max,&messageid,&op,&Len);
  if (res==0) {
    puts("scan_ldapmessage failed");
    return 1;
  }
  if (Len>1000 || Len+res>1000)  {
    puts("Response > 1000 bytes");
    return 1;
  }
  if (op!=BindResponse) {
    puts("op != BindResponse");
    return 1;
  }
  struct string matcheddn,errormessage,referral;
  res=scan_ldapbindresponse(buf+res,max,&result,&matcheddn,&errormessage,&referral);
  if (!res) {
    puts("scan_ldapbindresponse failed");
    return 1;
  }
  if (result) {
    printf("error: \"%.*s\"\n",(int)errormessage.l,errormessage.s);
    if (expecterror) return 0;
    return 1;
  }
  if (expecterror) return 1;
  return 0;
}
