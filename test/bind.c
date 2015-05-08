#include "ldap.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

static int ldapbind(const char* u,const char* p,int messageid) {
  char outbuf[1024];
  int s=100;
  if (!u) u="";
  if (!p) p="";
  if (strlen(u)>100 || strlen(p)>100)
    return 0;
  size_t len=fmt_ldapbindrequest(outbuf+s,3,u,p);
  size_t hlen=fmt_ldapmessage(0,messageid,BindRequest,len);
  fmt_ldapmessage(outbuf+s-hlen,messageid,BindRequest,len);
  if ((size_t)write(1,outbuf+s-hlen,len+hlen)!=len+hlen) return 0;;
  return 1;
}

int main(int argc,char* argv[]) {
  int messageid=0;
  const char* user=0;
  const char* passwd=0;
  for (;;) {
    int c=getopt(argc,argv,"u:p:m:");
    if (c==-1) break;
    switch (c) {
    case 'u':
      user=optarg;
      break;
    case 'p':
      passwd=optarg;
      break;
    case 'm':
      messageid=atoi(optarg);
      if (messageid<0) {
	puts("messageid must be a positive integer");
	return 1;
      }
      break;
    }
  }
  ldapbind(user,passwd,messageid);
}
