#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "byte.h"
#include "buffer.h"
#include "asn1.h"
#include "ldap.h"
#include "socket.h"
#include "ip4.h"
#include "str.h"

#include <fcntl.h>
#include <sys/socket.h>

#define BUFSIZE 8192

static long messageid=1;

static int ldapbind(int sock) {
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
  res=scan_ldapbindresponse(outbuf+res,outbuf+res+Len,&result,&matcheddn,&errormessage,&referral);
  if (!res) return 0;
  if (result) return 0;
  return 1;
}

int main(int argc,char* argv[]) {
  int sock;
  char buf[BUFSIZE];
  int len=0;
  char* me;
  long n,durchlauf;
  int bench;
  if ((me=strrchr(argv[0],'/')))
    ++me;
  else
    me=argv[0];
  if ((bench=!strcmp(me,"ldapbench"))) {
    n=atoi(getenv("NUM"));
    buffer_putsflush(buffer_2,"benchmark mode\n");
  }

  if (argc<4) {
usage:
    buffer_putsflush(buffer_2,"usage: ldapclient ip baseObject filter [foo...]\n");
    return 0;
  }
  if (!bench) n=1;
  for (durchlauf=0; durchlauf<n; ++durchlauf) {
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
      struct Filter *f;
      struct AttributeDescriptionList adl;
      struct AttributeDescriptionList *next;
      struct SearchRequest sr;
      int i;
      if (!scan_ldapsearchfilterstring(argv[3],&f)) {
	buffer_putsflush(buffer_2,"could not parse filter!\n");
	close(sock);
	return 1;
      }
      i=4; /* This should be the first index to an attribute argument in argv[] */
      if (argc>4) {
	adl.a.s=argv[i];
	adl.a.l=str_len(argv[i]);
	next=&adl;
	++i;
	while (i<argc) {
	  struct AttributeDescriptionList *n;
	  n=malloc(sizeof(struct AttributeDescriptionList));
	  n->a.s=argv[i]; n->a.l=str_len(argv[i]);
	  n->next=0;
	  next->next=n;
	  next=n;

#if 0
	  buffer_puts(buffer_2,"requesting ");
	  buffer_puts(buffer_2,argv[i]);
	  buffer_putnlflush(buffer_2);
#endif

	  i++;
	}
	sr.attributes=&adl;
      } else {
	sr.attributes=0;
      }
      sr.baseObject.s=argv[2]; sr.baseObject.l=str_len(sr.baseObject.s);
      sr.scope=wholeSubtree; sr.derefAliases=neverDerefAliases;
      sr.sizeLimit=sr.timeLimit=sr.typesOnly=0;
      sr.filter=f;
      len=fmt_ldapsearchrequest(buf+100,&sr);
      {
	int tmp=fmt_ldapmessage(0,++messageid,SearchRequest,len);
	fmt_ldapmessage(buf+100-tmp,messageid,SearchRequest,len);
	write(sock,buf+100-tmp,len+tmp);
      }
      shutdown(sock,SHUT_WR);
      {
	char buf[8192];	/* arbitrary limit, bad! */
	int len=0,tmp,tmp2;
	char* max;
	struct SearchResultEntry sre;
	int matches=0;
	len=0;
	for (;;) {
	  long slen,mid,op;
	  int cur=0;

	  tmp=read(sock,buf+len,sizeof(buf)-len);

#if 0
	  buffer_puts(buffer_2,"DEBUG: read ");
	  buffer_putulong(buffer_2,tmp);
	  buffer_putsflush(buffer_2," bytes.\n");
#endif

	  if (tmp<=0) {
	    buffer_putsflush(buffer_2,"read error.\n");
	    return 0;
	  }
  //	cur=len;
	  len+=tmp;
nextmessage:
	  if ((tmp2=scan_ldapmessage(buf+cur,buf+len,&mid,&op,&slen))) {
	    max=buf+cur+slen+tmp2;
	    if (op==SearchResultEntry) {
	      ++matches;
	      if ((tmp=scan_ldapsearchresultentry(buf+cur+tmp2,max,&sre))) {
		struct PartialAttributeList* pal=sre.attributes;

#if 0
		buffer_puts(buffer_2,"DEBUG: sre size ");
		buffer_putulong(buffer_2,tmp);
		buffer_putsflush(buffer_2,".\n");
#endif

		if (durchlauf==0) {
		  buffer_puts(buffer_1,"dn: ");
		  buffer_put(buffer_1,sre.objectName.s,sre.objectName.l);
		  buffer_puts(buffer_1,"\n");
		  while (pal) {
		    struct AttributeDescriptionList* adl=pal->values;
		    do {
		      buffer_puts(buffer_1,"  ");
		      buffer_put(buffer_1,pal->type.s,pal->type.l);
		      buffer_puts(buffer_1,": ");
		      if (adl) {
			buffer_put(buffer_1,adl->a.s,adl->a.l);
			buffer_puts(buffer_1,"\n");
			adl=adl->next;
			if (!adl) break;
		      }
		    } while (adl);
		    pal=pal->next;
		  }
		  buffer_putsflush(buffer_1,"\n");
		}
		free_ldapsearchresultentry(&sre);
	      } else {
		buffer_putsflush(buffer_2,"goto\n");
		goto copypartialandcontinue;
	      }
	    } else if (op==SearchResultDone) {
	      if (!matches)
		buffer_putsflush(buffer_2,"no matches.\n");
	      if (bench && durchlauf!=0)
		write(1,"+",1);
	      break;
//	      return 0;
	    } else {
	      buffer_putsflush(buffer_2,"unexpected response.\n");
	      return 0;
	    }
	    if (max<buf+len) {
	      cur+=slen+tmp2;
	      goto nextmessage;
	    } else {
	      len=0;
	    }
	  } else {
	    /* copy partial message */
copypartialandcontinue:
	    byte_copy(buf,len-cur,buf+cur);
	    len-=cur; cur=0;
	  }
	}

#if 0
	{
	  int fd=open("/tmp/searchresultentry",O_WRONLY|O_CREAT,0600);
	  write(fd,buf+tmp2,max-buf+tmp2);
	  close(fd);
	}
#endif
      }
    } else {
      buffer_putsflush(buffer_2,"ldapbind failed\n");
      return 2;
    }
    close(sock);
  }
  if (bench) write(1,"\n",1);
  return 0;
}
