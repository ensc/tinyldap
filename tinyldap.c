#include <unistd.h>
#include <stdlib.h>
#include "byte.h"
#include "buffer.h"
#include "ldap.h"
#include "ldif.h"
#include "open.h"
#include "mmap.h"
#include "uint32.h"
#ifdef STANDALONE
#include "socket.h"
#include "ip6.h"
#include <wait.h>
#endif

static int verbose=0;
char* map;
long filelen;
uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;

#define BUFSIZE 8192

static int indexable(struct Filter* f) {
  struct Filter* y=f->x;
  if (!f) return 1;
  switch (f->type) {
  case AND:
    while (y) {
      if (!indexable(y)) return 0;
      y=y->next;
    }
    return 1;
  case OR:
    while (y) {
      if (!indexable(y)) return 0;
      y=y->next;
    }
    return 1;
#if 0
  /* doesn't make much sense to try to speed up negated queries */
  case NOT:
    return indexable(y);
#endif
  case SUBSTRING:
    if (f->substrings->substrtype!=prefix) return 0;
    /* fall through */
  case EQUAL:
    {
      uint32 ofs;
      for (ofs=indices_offset+record_count*4; ofs<(unsigned long)filelen;) {
	uint32 index_type,next,indexed_attribute;
	uint32_unpack(map+ofs,&index_type);
	uint32_unpack(map+ofs+4,&next);
	uint32_unpack(map+ofs+8,&indexed_attribute);
	if (index_type==0)
	  if (matchstring(&f->ava.desc,map+indexed_attribute))
	    return 1;
	ofs=next;
      }
    }
    /* fall through */
  default:
    return 0;
  }
}

#define MAXINDEXMATCHES 100
static uint32 matches[MAXINDEXMATCHES];
static uint32 matchcounter;

/* find record given a data pointer */
static uint32 findrec(uint32 dat) {
  uint32* records=(uint32*)(map+indices_offset);
  uint32 bottom=0;
  uint32 top=record_count;
  while ((top>=bottom)) {
    uint32 mid=(top+bottom)/2;
    uint32 k,l;
    uint32_unpack(&records[mid],&k);
    uint32_unpack(map+k+8,&l);
    if (l<dat) {
      uint32_unpack(map+k,&l);
      uint32_unpack(map+k+l*8+4,&l);
      if (l>dat) return k;	/* found! */
      bottom=mid+1;
    } else
      top=mid-1;
  }
  return 0;
}

static void answerwith(uint32 ofs,struct SearchRequest* sr,long messageid,int out) {
  uint32 k;
  struct SearchResultEntry sre;
  struct PartialAttributeList** pal=&sre.attributes;

  if (0) {
    char* x=map+ofs;
    uint32 j,k;
    uint32_unpack(x,&j);
    buffer_putulong(buffer_2,j);
    buffer_puts(buffer_2," attributes:\n");
    x+=8;
    buffer_puts(buffer_2,"  dn: ");
    uint32_unpack(x,&k);
    buffer_puts(buffer_2,map+k);
    buffer_puts(buffer_2,"\n  objectClass: ");
    x+=4;
    uint32_unpack(x,&k);
    buffer_puts(buffer_2,map+k);
    buffer_puts(buffer_2,"\n");
    x+=4;
    for (; j>2; --j) {
      uint32_unpack(x,&k);
      buffer_puts(buffer_2,"  ");
      buffer_puts(buffer_2,map+k);
      buffer_puts(buffer_2,": ");
      uint32_unpack(x+4,&k);
      buffer_puts(buffer_2,map+k);
      buffer_puts(buffer_2,"\n");
      x+=8;
    }
    buffer_flush(buffer_2);
  }

  uint32_unpack(map+ofs+8,&k);
  sre.objectName.s=map+k; sre.objectName.l=strlen(map+k);
  sre.attributes=0;
  /* now go through list of requested attributes */
  {
    struct AttributeDescriptionList* adl=sr->attributes;
    while (adl) {
      const char* val=0;
      uint32 i=2,j;
      uint32_unpack(map+ofs,&j);
#if 0
      buffer_puts(buffer_2,"looking for attribute \"");
      buffer_put(buffer_2,adl->a.s,adl->a.l);
      buffer_putsflush(buffer_2,"\"\n");
#endif
      if (!matchstring(&adl->a,"dn")) val=sre.objectName.s; else
      if (!matchstring(&adl->a,"objectClass")) {
	uint32_unpack(map+ofs+12,&k);
	val=map+k;
      } else {
	for (; i<j; ++i) {
	  uint32_unpack(map+ofs+i*8,&k);
	  if (!matchstring(&adl->a,map+k)) {
	    uint32_unpack(map+ofs+i*8+4,&k);
	    val=map+k;
	    break;
	  }
	}
      }
      if (val) {
	*pal=malloc(sizeof(struct PartialAttributeList));
	if (!*pal) {
nomem:
	  buffer_putsflush(buffer_2,"out of virtual memory!\n");
	  exit(1);
	}
	(*pal)->type=adl->a;
	{
	  struct AttributeDescriptionList** a=&(*pal)->values;
	  while (i<j) {
	    *a=malloc(sizeof(struct AttributeDescriptionList));
	    if (!*a) goto nomem;
	    (*a)->a.s=val;
	    (*a)->a.l=strlen(val);
	    (*a)->next=0;
	    for (;i<j; ++i) {
	      uint32_unpack(map+ofs+i*8,&k);
	      if (!matchstring(&adl->a,map+k)) {
		uint32_unpack(map+ofs+i*8+4,&k);
		val=map+k;
		++i;
		break;
	      }
	    }
	  }
	}
	(*pal)->next=0;
	pal=&(*pal)->next;
      }
      adl=adl->next;
    }
  }
  {
    long l=fmt_ldapsearchresultentry(0,&sre);
    char *buf=alloca(l+300); /* you never know ;) */
    long tmp;
    if (verbose) {
      buffer_puts(buffer_2,"sre len ");
      buffer_putulong(buffer_2,l);
      buffer_putsflush(buffer_2,".\n");
    }
    tmp=fmt_ldapmessage(buf,messageid,SearchResultEntry,l);
    fmt_ldapsearchresultentry(buf+tmp,&sre);
    write(out,buf,l+tmp);
  }
}

int handle(int in,int out) {
  int len;
  char buf[BUFSIZE];
  for (len=0;;) {
    int tmp=read(in,buf+len,BUFSIZE-len);
    int res;
    long messageid,op,Len;
    if (tmp==0)
      if (!len) { return 0; }
    if (tmp<0) { write(2,"error!\n",7); return 1; }
    len+=tmp;
    res=scan_ldapmessage(buf,buf+len,&messageid,&op,&Len);
    if (res>0) {
      if (verbose) {
	buffer_puts(buffer_2,"got message of length ");
	buffer_putulong(buffer_2,Len);
	buffer_puts(buffer_2," with id ");
	buffer_putulong(buffer_2,messageid);
	buffer_puts(buffer_2,": op ");
	buffer_putulong(buffer_2,op);
	buffer_putsflush(buffer_2,".\n");
      }
      switch (op) {
      case BindRequest:
	{
	  long version,method;
	  struct string name;
	  int tmp;
	  tmp=scan_ldapbindrequest(buf+res,buf+res+len,&version,&name,&method);
	  if (tmp>=0) {
	    if (verbose) {
	      buffer_puts(buffer_2,"bind request: version ");
	      buffer_putulong(buffer_2,version);
	      buffer_puts(buffer_2," for name \"");
	      buffer_put(buffer_2,name.s,name.l);
	      buffer_puts(buffer_2,"\" with method ");
	      buffer_putulong(buffer_2,method);
	      buffer_putsflush(buffer_2,".\n");
	    }
	    {
	      char outbuf[1024];
	      int s=100;
	      int len=fmt_ldapbindresponse(outbuf+s,0,"","go ahead","");
	      int hlen=fmt_ldapmessage(0,messageid,BindResponse,len);
	      fmt_ldapmessage(outbuf+s-hlen,messageid,BindResponse,len);
	      write(out,outbuf+s-hlen,len+hlen);
	    }
	  }
	}
	break;
      case SearchRequest:
	{
	  struct SearchRequest sr;
	  int tmp;
#if 0
	  {
	    int fd=open_write("request");
	    write(fd,buf,res+len);
	    close(fd);
	  }
#endif
	  if ((tmp=scan_ldapsearchrequest(buf+res,buf+res+len,&sr))) {
	    if (indexable(sr.filter)) {
	      buffer_putsflush(buffer_2,"query is indexable!\n");
	      /* Use the index to find matching data.  Put the offsets
	       * of the matches in a table.  Use findrec to locate
	       * the records that point to the data. */
	    } /* else */ {
	      char* x=map+5*4+size_of_string_table+attribute_count*8;
	      unsigned long i;
	      for (i=0; i<record_count; ++i) {
		uint32 j;
		uint32_unpack(x,&j);
		if (ldap_match_mapped(x-map,&sr))
		  answerwith(x-map,&sr,messageid,out);
		x+=j*8;
	      }
	    }
	  } else {
	    buffer_putsflush(buffer_2,"couldn't parse search request!\n");
	    exit(1);
	  }
	  {
	    char buf[1000];
	    long l=fmt_ldapsearchresultdone(buf+100,0,"","","");
	    int hlen=fmt_ldapmessage(0,messageid,SearchResultDone,l);
	    fmt_ldapmessage(buf+100-hlen,messageid,SearchResultDone,l);
	    write(out,buf+100-hlen,l+hlen);
	  }
	}
	break;
      default:
	exit(1);
      }
      Len+=res;
#if 0
      buffer_puts(buffer_2,"byte_copy(buf,");
      buffer_putulong(buffer_2,len-Len);
      buffer_puts(buffer_2,",buf+");
      buffer_putulong(buffer_2,Len);
      buffer_putsflush(buffer_2,");\n");
#endif
      if (Len<len) {
	byte_copy(buf,len-Len,buf+Len);
	len-=Len;
      } else len=0;
    } else
      exit(2);
  }
}

int main() {
#ifdef STANDALONE
  int sock;
#endif

  map=mmap_read("data",&filelen);
  if (!map) {
    buffer_putsflush(buffer_2,"could not open data!\n");
    return 1;
  }
  uint32_unpack(map,&magic);
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);

#if 0
  ldif_parse("exp.ldif");
  if (!first) {
    buffer_putsflush(buffer_2,"no data?!");
  }
#endif

#ifdef STANDALONE
  if ((sock=socket_tcp6())==-1) {
    buffer_putsflush(buffer_2,"socket failed!\n");
    exit(1);
  }
  if (socket_bind6_reuse(sock,V6any,389,0)) {
    buffer_putsflush(buffer_2,"bind failed!\n");
    exit(1);
  }
  if (socket_listen(sock,32)) {
    buffer_putsflush(buffer_2,"listen failed!\n");
    exit(1);
  }
  for (;;) {
    char ip[16];
    uint16 port;
    uint32 scope_id;
    int asock;
    {
      int status;
      while ((status=waitpid(-1,0,WNOHANG))!=0 && status!=(pid_t)-1); /* reap zombies */
    }
    asock=socket_accept6(sock,ip,&port,&scope_id);
    if (asock==-1) {
      buffer_putsflush(buffer_2,"accept failed!\n");
      exit(1);
    }
#ifdef DEBUG
    handle(asock,asock);
    exit(0);
#else
#endif
    switch (fork()) {
    case -1: buffer_putsflush(buffer_2,"fork failed!\n"); exit(1);
    case 0: /* child */
      handle(asock,asock);
      exit(0); /* not reached */
    default:
      close(asock);
    }
  }
#else
  handle(0,1);
#endif
  return 0;
}
