#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <libowfat/byte.h>
#include <libowfat/buffer.h>
#include "ldap.h"
#include <libowfat/socket.h>
#include <libowfat/ip4.h>
#include <libowfat/str.h>
#include <libowfat/open.h>

#define BUFSIZE 8192

static unsigned long messageid=1;

static int ldapbind(int sock) {
  char outbuf[1024];
  int s=100;
  int len=fmt_ldapbindrequest(outbuf+s,3,"","");
  int hlen=fmt_ldapmessage(0,messageid,BindRequest,len);
  int res;
  unsigned long op,result;
  size_t Len;
  struct string matcheddn,errormessage,referral;
  fmt_ldapmessage(outbuf+s-hlen,messageid,BindRequest,len);
  if (write(sock,outbuf+s-hlen,len+hlen)!=len+hlen) return 0;;
  len=read(sock,outbuf,1024);
  res=scan_ldapmessage(outbuf,outbuf+len,&messageid,&op,&Len);
  if (!res) return 0;
  if (op!=BindResponse) return 0;
  res=scan_ldapbindresponse(outbuf+res,outbuf+res+Len,&result,&matcheddn,&errormessage,&referral);
  if (!res) return 0;
  if (result) return 0;
  return 1;
}

int main(int argc,char* argv[]) {
  int sock;
  char buf[BUFSIZE];
  int len=0;

  if (argc<4) {
usage:
    buffer_putsflush(buffer_2,"usage: ldapclient_src ip baseObject Attrib Prefix\n");
    return 0;
  }
  sock=socket_tcp4b();
  {
    char ip[4];
    if (argv[1][scan_ip4(argv[1],ip)]) goto usage;
    if (socket_connect4(sock,ip,389) && !argv[5]) {
      buffer_putsflush(buffer_2,"could not connect to ldap server!\n");
      return 1;
    }
  }
  if (argv[5] || ldapbind(sock)) {
    struct Filter f;
    struct AttributeDescriptionList adl;
    struct SearchRequest sr;
    struct Substring ssr;
    f.x=f.next=0;
    f.type=SUBSTRING;
    f.ava.desc.s=argv[3]; f.ava.desc.l=str_len(argv[3]);
    // if (argv[3][f.ava.desc.l] != '=') goto usage;
    //f.ava.value.s=argv[3]+f.ava.desc.l+1; f.ava.value.l=str_len(f.ava.value.s);
    f.ava.value.s="";
    f.ava.value.l=0;
    ssr.substrtype=prefix;
    ssr.s.s=argv[4];
    ssr.s.l=str_len(ssr.s.s);
    ssr.next=0;
    f.a=&adl;
    //f.a=0;
    f.substrings=&ssr;
    adl.a.s="mail"; adl.a.l=4;
    adl.next=0;
    sr.baseObject.s=argv[2]; sr.baseObject.l=str_len(sr.baseObject.s);
    sr.scope=wholeSubtree; sr.derefAliases=neverDerefAliases;
    sr.sizeLimit=sr.timeLimit=sr.typesOnly=0;
    sr.filter=&f;
    sr.attributes=&adl;
    len=fmt_ldapsearchrequest(buf+100,&sr);
    {
      int tmp=fmt_ldapmessage(0,++messageid,SearchRequest,len);
      fmt_ldapmessage(buf+100-tmp,messageid,SearchRequest,len);
      if (argv[5]) { int w; 
	puts("writing file");
	w=open_trunc(argv[5]);
	write(w,buf+100-tmp,len+tmp);
	close(w);
	return 0;
      }
      write(sock,buf+100-tmp,len+tmp);
    }
    {
      char buf[8192];	/* arbitrary limit, bad! */
      int len=0,tmp,tmp2;
      char* max;
      struct SearchResultEntry sre;
      for (;;) {
	unsigned long mid,op;
	size_t slen;
	tmp=read(sock,buf+len,sizeof(buf)-len);
	if (tmp<=0) {
	  buffer_putsflush(buffer_2,"read error.\n");
	  return 0;
	}
	len+=tmp;
	if ((tmp2=scan_ldapmessage(buf,buf+len,&mid,&op,&slen))) {
	  max=buf+slen+tmp2;
	  if (op==SearchResultEntry) break;
	  if (op==SearchResultDone) {
	    buffer_putsflush(buffer_2,"no matches.\n");
	    return 0;
	  } else {
	    buffer_putsflush(buffer_2,"unexpected response.\n");
	    return 0;
	  }
	}
      }
      if ((tmp=scan_ldapsearchresultentry(buf+tmp2,max,&sre))) {
	struct PartialAttributeList* pal=sre.attributes;
	buffer_puts(buffer_1,"objectName \"");
	buffer_put(buffer_1,sre.objectName.s,sre.objectName.l);
	buffer_puts(buffer_1,"\"\n");
	while (pal) {
	  struct AttributeDescriptionList* adl=pal->values;
	  buffer_puts(buffer_1,"  ");
	  buffer_put(buffer_1,pal->type.s,pal->type.l);
	  buffer_puts(buffer_1,":");
	  while (adl) {
	    buffer_put(buffer_1,adl->a.s,adl->a.l);
	    if (adl->next) buffer_puts(buffer_1,", ");
	    adl=adl->next;
	  }
	  buffer_putsflush(buffer_1,"\n");
	  pal=pal->next;
	}
      } else
	buffer_putsflush(buffer_1,"punt!\n");
    }
  } else {
    buffer_putsflush(buffer_2,"ldapbind failed\n");
    return 2;
  }
  return 0;
}
