#include <alloca.h>
#include <buffer.h>
#include <scan.h>
#include <open.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "mduptab.h"
#include "mstorage.h"
#include "str.h"
#include "ldif.h"
#include "byte.h"
#include "textcode.h"
#include "stralloc.h"

mduptab_t attributes,classes;
mstorage_t stringtable;
long dn, objectClass;

/* this is called after each record.
 * If it returns -1, ldif_parse will exit immediately.
 * If it returns 0, ldif_parse will continue parsing and overwrite the
 *   current ldaprec.
 * If it returns 1, ldif_parse will allocate a new ldaprec and link it
 *   using the next pointer in the current ldaprec.
 * If the callback is NULL, a callback that always returns 1 is assumed.
 * */
int (*ldif_parse_callback)(struct ldaprec* l);

unsigned long ldifrecords;

static void addattribute(struct ldaprec** l,long name,long val) {
  if (name==dn) (*l)->dn=val; else
    if ((*l)->n<ATTRIBS) {
      (*l)->a[(*l)->n].name=name;
      (*l)->a[(*l)->n].value=val;
      ++(*l)->n;
    } else {
      buffer_puts(buffer_2,"LDIF parse error: too many attributes!:\n  ");
      buffer_puts(buffer_2,attributes.Strings->root+name);
      buffer_puts(buffer_2,"\nat dn\n  ");
      buffer_puts(buffer_2,(*l)->dn+stringtable.root);
      buffer_putnlflush(buffer_2);
      exit(1);
    }
}

/* "ou=fnord; O=fefe; c=de" -> "ou=fnord,o=fefe,c=de" */
/* returns the length of the new string */
static int normalize_dn(char* dest,const char* src,int len) {
  int makelower=1;
  char* orig=dest;
  while (len) {
    if (*src==';' || *src==',') {
      *dest=',';
      while (len>1 && src[1]==' ') { ++src; --len; }
      makelower=1;
    } else {
      if (makelower)
	*dest=tolower(*src);
      else
	*dest=*src;
      if (*dest=='=') makelower=0;
    }
    ++dest;
    ++src;
    --len;
  }
  return dest-orig;
}

static int unbase64(char* buf) {
  unsigned long destlen;
  char temp[8192];
  long l=scan_base64(buf,temp,&destlen);
  if (buf[l] && buf[l]!='\n') return 0;
  byte_copy(buf,destlen,temp);
  return destlen;
}


static inline int add_normalized(const char* s,long len) {
  char* newdn=alloca(len+1);
  long val;
  if ((val=mstorage_add(&stringtable,newdn,normalize_dn(newdn,s,len)))<0) return -1;
  return val;
}

static int parserec(buffer* b, struct ldaprec** l) {
  char buf[8192];
  int n,i,eof=0,ofs=0;
  unsigned int i2;
  int len,base64,binary;
  stralloc payload={0,0,0};

  if (!(*l=malloc(sizeof(struct ldaprec)))) {
nomem:
    buffer_putsflush(buffer_2,"out of memory!\n");
    return 1;
  }
  (*l)->dn=-1;
  (*l)->next=0; (*l)->n=0;
  ldifrecords=0;
  do {
    long tmp, val;
    base64=binary=0;
    n=ofs+buffer_get_token(b,buf+ofs,8192-ofs,":",1);
    if (n==0) break;
    i=scan_whitenskip(buf,n);
    buf[n]=0;
    if ((i2=str_chr(buf,';'))<(unsigned int)n) {
      buf[i2]=0;
      if (str_equal("binary",buf+i2+1)) binary=1;
    }
    if ((tmp=mduptab_adds(&attributes,buf+i))<0) goto nomem;
    if (!stralloc_copys(&payload,"")) goto nomem;
    {
      char dummy;
      int res;
      /* read line, skipping initial whitespace */
      for (n=0; (res=buffer_getc(b,&dummy))==1; ) {
	if (dummy=='\n') break;
	if (!n && dummy==':' && base64==0) { base64=1; continue; }
	if (!n && (dummy==' ' || dummy=='\t')) continue;
	if (!stralloc_append(&payload,&dummy)) goto nomem;
	++n;
      }
      if (res==-1) return 1;
    }

lookagain:
    {
      char c;
      switch (buffer_getc(b,&c)) {
      case 0: eof=1; break;
      case -1: buffer_putsflush(buffer_2,"read error!\n"); return 1;
      }
      if (c==' ') {	/* continuation */
//	puts("continuation!");
	n=buffer_get_token(b,buf,8192,"\n",1);
	if (n==-1) return 1;
	if (!stralloc_catb(&payload,buf,n)) goto nomem;
	goto lookagain;
      } else if (c=='\n') {
	struct ldaprec* m;

	if (payload.len) {
	  if (!stralloc_0(&payload)) goto nomem;
	  if (base64) {
	    len=unbase64(payload.s);
	    if (!binary) { payload.s[len]=0; ++len; }
	  } else
	    len=n+1;
	} else
	  len=0;

#if 0
	buffer_puts(buffer_2,"feld \"");
	buffer_puts(buffer_2,attributes.Strings->root+tmp);
	buffer_puts(buffer_2,"\", wert \"");
	buffer_put(buffer_2,payload.s,len);
	buffer_putsflush(buffer_2,"\".\n");
#endif

	if (tmp==objectClass) {
	  if ((val=mduptab_add(&classes,payload.s,len-1))<0) goto nomem;
	} else if (tmp==dn) {
	  if ((val=add_normalized(payload.s,len))==-1) goto nomem;
	} else
	  if ((val=mstorage_add_bin(&stringtable,payload.s,len))<0) goto nomem;
	addattribute(l,tmp,val);

	m=0;
	if (ldif_parse_callback) {
	  switch (ldif_parse_callback(*l)) {
	  case -1:
	    return -1;
	  case 0:
	    m=*l;
	    break;
#if 0
	  case 1:
	    m=0;
	    break;
#endif
	  }
	}
	if (!m) if (!(m=malloc(sizeof(struct ldaprec)))) return 2;

	(*l)->next=m;
	m->n=0; m->dn=-1; m->next=0;
	ofs=0;
//	dumprec(*l);
	if (*l!=m) l=&((*l)->next);
	++ldifrecords;
	continue;
      } else {
	ofs=1;
	buf[0]=c;
      }
    }
//    buf[n]=0;
#if 1

    if (payload.len) {
      if (!stralloc_0(&payload)) goto nomem;
      if (base64) {
	len=unbase64(payload.s);
	if (!binary) { payload.s[len]=0; ++len; }
      } else
	len=n+1;
    } else
      len=0;

#if 0
	buffer_puts(buffer_2,"feld \"");
	buffer_puts(buffer_2,attributes.Strings->root+tmp);
	buffer_puts(buffer_2,"\", wert \"");
	buffer_put(buffer_2,payload.s,len);
	buffer_putsflush(buffer_2,"\".\n");
#endif

    if (tmp==objectClass) {
      if ((val=mduptab_add(&classes,payload.s,len-1))<0) goto nomem;
    } else if (tmp==dn) {
      if ((val=add_normalized(payload.s,payload.len))==-1) goto nomem;
    } else
      if ((val=mstorage_add_bin(&stringtable,payload.s,payload.len))<0) goto nomem;
    addattribute(l,tmp,val);
#endif
  } while (!eof);
  if (ldif_parse_callback && ldif_parse_callback(*l)==-1) return -1;
  if ((*l)->dn<0 && ((*l)->next)) {
    struct ldaprec* m=(*l)->next;
    free((*l));
    (*l)=m;
  }
  return 0;
}

struct ldaprec *first=0;

int ldif_parse(const char* filename) {
  char buf[4096];
  int fd;
  buffer in;
  buffer* tmp;
  if (filename[0]=='-' && !filename[1]) {
    tmp=buffer_0;
    fd=-1;
  } else {
    fd=open_read(filename);
    if (fd<0) return 1;
    buffer_init(&in,read,fd,buf,sizeof buf);
    tmp=&in;
  }
  dn=mduptab_adds(&attributes,"dn");
  objectClass=mduptab_adds(&attributes,"objectClass");
  {
    int res=parserec(tmp,&first);
    if (fd!=-1) close(fd);
    return res;
  }
}

