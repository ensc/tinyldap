#include <unistd.h>
#include "byte.h"
#include "buffer.h"
#include "ldap.h"
#include "socket.h"
#include "ip4.h"

#define BUFSIZE 8192

static long messageid=1;

int ldapbind(int sock) {
  char outbuf[1024];
  int s=100;
  int len=fmt_ldapbindrequest(outbuf+s,3,"","");
  int hlen=fmt_ldapmessage(0,messageid,BindRequest,len);
  int res;
  long op,Len,result;
  struct string matcheddn,errormessage,referral;
  fmt_ldapmessage(outbuf+s-hlen,messageid,BindRequest,len);
  if (write(sock,outbuf+s-hlen,len+hlen)!=len+hlen) return 0;;
  len=read(sock,outbuf,1024);
  res=scan_ldapmessage(outbuf,outbuf+len,&messageid,&op,&Len);
  if (!res) return 0;
  if (op!=BindResponse) return 0;
  res=scan_ldapbindresponse(outbuf+res,outbuf+res+len,&result,&matcheddn,&errormessage,&referral);
  if (!res) return 0;
  if (result) return 0;
  return 1;
}

int main(int argc,char* argv[]) {
  int sock;
  char buf[BUFSIZE];
  int len=0;

  if (argc<3) {
usage:
    buffer_putsflush(buffer_2,"usage: ldapclient ip baseObject foo=bar [baz...]\n");
    return 0;
  }
  sock=socket_tcp4();
  {
    char ip[4];
    if (argv[1][scan_ip4(argv[1],ip)]) goto usage;
    if (socket_connect4(sock,ip,389)) {
      buffer_putsflush(buffer_2,"could not connect to ldap server!\n");
      return 1;
    }
  }
  if (ldapbind(sock)) {
    struct Filter f;
    struct AttributeDescriptionList adl;
    struct SearchRequest sr;
    f.x=f.next=0;
    f.type=EQUAL;
    f.ava.desc.s=argv[3]; f.ava.desc.l=str_chr(argv[3],'=');
    if (argv[3][f.ava.desc.l] != '=') goto usage;
    f.ava.value.s=argv[3]+f.ava.desc.l+1; f.ava.value.l=5;
    f.a=&adl;
    adl.a.s="mail"; adl.a.l=4;
    adl.next=0;
    sr.baseObject.s=argv[2]; sr.baseObject.l=strlen(sr.baseObject.s);
    sr.scope=wholeSubtree; sr.derefAliases=neverDerefAliases;
    sr.sizeLimit=sr.timeLimit=sr.typesOnly=0;
    sr.filter=&f;
    sr.attributes=&adl;
    len=fmt_ldapsearchrequest(buf+100,&sr);
    {
      int tmp=fmt_ldapmessage(buf,++messageid,SearchRequest,len);
      fmt_ldapmessage(buf+100-tmp,messageid,SearchRequest,len);
      write(sock,buf+100-tmp,len+tmp);
    }
  } else {
    buffer_putsflush(buffer_2,"ldapbind failed\n");
    return 2;
  }
}
