#define _FILE_OFFSET_BITS 64
#include <alloca.h>
#include <libowfat/buffer.h>
#include <libowfat/scan.h>
#include <libowfat/open.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "mduptab.h"
#include "mstorage.h"
#include <libowfat/str.h>
#include "ldif.h"
#include <libowfat/byte.h>
#include <libowfat/textcode.h>
#include <libowfat/stralloc.h>
#include <libowfat/uint32.h>

mduptab_t attributes,classes;
mstorage_t stringtable;
uint32_t dn, objectClass;
unsigned long lines;

unsigned long recstart;

/* this is called after each record.
 * If it returns -1, ldif_parse will exit immediately.
 * If it returns 0, ldif_parse will continue parsing and overwrite the
 *   current ldaprec.
 * If it returns 1, ldif_parse will allocate a new ldaprec and link it
 *   using the next pointer in the current ldaprec.
 * If the callback is NULL, a callback that always returns 1 is assumed.
 * */
int (*ldif_parse_callback)(struct ldaprec* l);
uint32_t (*ldif_addstring_callback)(const char* s,unsigned long len);

unsigned long ldifrecords;

static void addattribute(struct ldaprec** l,uint32_t name,uint32_t val) {
  if (name==dn) (*l)->dn=val; else
    if ((*l)->n<ATTRIBS) {
      (*l)->a[(*l)->n].name=name;
      (*l)->a[(*l)->n].value=val;
      ++(*l)->n;
    } else {
      buffer_puts(buffer_2,"\r\n\nLDIF parse error: too many attributes!: ");
      buffer_puts(buffer_2,attributes.Strings->root+name);
      buffer_puts(buffer_2," in line ");
      buffer_putulong(buffer_2,lines);
      buffer_putnlflush(buffer_2);
      exit(1);
    }
}

static size_t unbase64(char* buf) {
  size_t destlen;
  char temp[8192];
  size_t l=scan_base64(buf,temp,&destlen);
  if (buf[l] && buf[l]!='\n') return 0;
  byte_copy(buf,destlen,temp);
  return destlen;
}

uint32_t (*ldif_addstring_callback)(const char* s,unsigned long len);

static uint32_t addstring(const char* s,unsigned long len) {
  return mstorage_add(&stringtable,s,len);
}

static long commit_string_bin(const char* s,unsigned long n) {
  unsigned int i;
  static char zero;
  uint32_t x;
  char intbuf[4];
  if (n==0 || (n==1 && s[0]==0)) goto encodebinary;
  for (i=0; i<n-1; ++i)
    if (!s[i]) {
encodebinary:
      uint32_pack(intbuf,n);
      if ((x=ldif_addstring_callback(&zero,1))==(uint32_t)-1 || ldif_addstring_callback(intbuf,4)==(uint32_t)-1 || ldif_addstring_callback(s,n)==(uint32_t)-1) return -1;
      return x;
    }
  x=ldif_addstring_callback(s,n);
  if (s[n-1])
    if (ldif_addstring_callback(&zero,1)==(uint32_t)-1) return -1;
  return x;
}


static inline int add_normalized(const char* s,long len) {
  char* newdn=alloca(len+1);
  long val;
  if ((val=ldif_addstring_callback(newdn,normalize_dn(newdn,s,len)))<0) return -1;
  return val;
}

static int parserec(buffer* b, struct ldaprec** l,const char* filename) {
  char buf[8192];
  int n,i,eof=0,ofs=0;
  unsigned int i2;
  size_t len,base64,binary;
  stralloc payload={0,0,0};

  if (!(*l=malloc(sizeof(struct ldaprec)))) {
nomem:
    buffer_putsflush(buffer_2,"\r\n\nout of memory!\n");
    return 1;
  }
  (*l)->dn=-1;
  (*l)->next=0; (*l)->n=0;
  ldifrecords=0;
  do {
    uint32_t tmp, val;
    base64=binary=0;
    buf[ofs]=0;
    n=ofs+buffer_get_token(b,buf+ofs,8192-ofs,":\n",2);
    if (n==ofs) {
      if (buf[ofs]==0) eof=1;
      break;
    }
    if (buf[0]=='#') {	/* comment line */
      while (n>=8192-ofs || buf[n]==':') {
	/* if we got a partial line or the comment contained a colon, do over */
	ofs=0;
	n=buffer_get_token(b,buf,8192,"\n",1);
      }
      ++lines;
      continue;
    }
    i=scan_whitenskip(buf,n);
    if (buf[byte_chr(buf+i,n-i,'\n')]=='\n') {
      buffer_putm(buffer_2,"\r\n\n",filename,":");
      buffer_putulong(buffer_2,lines+1);
      buffer_putsflush(buffer_2,": error: no key:value found\n");
      exit(1);
    }
    buf[n]=0;
    if ((i2=str_chr(buf,';'))<(unsigned int)n) {
      buf[i2]=0;
      if (str_equal("binary",buf+i2+1)) binary=1;
    }
    if ((tmp=mduptab_adds(&attributes,buf+i))==(uint32_t)-1) {
//      write(2,"a",1);
      goto nomem;
    } if (!stralloc_copys(&payload,"")) {
//      write(2,"b",1);
      goto nomem;
    }
    {
      char dummy;
      int res;
      /* read line, skipping initial whitespace */
//      for (n=0; (res=buffer_getc(b,&dummy))==1; ) {
      for (n=0; (res=buffer_GETC(b,&dummy))==1; ) {
	if (dummy=='\n') { ++lines; break; }
	if (!n && dummy==':' && base64==0) { base64=1; continue; }
	if (!n && (dummy==' ' || dummy=='\t')) continue;
	if (!stralloc_APPEND(&payload,&dummy)) {
//	  write(2,"c",1);
	  goto nomem;
	}
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
	if (!stralloc_catb(&payload,buf,n)) {
//	  write(2,"d",1);
	  goto nomem;
	}
	if (!eof) goto lookagain;
      } else if (c=='\n') {
	struct ldaprec* m;

	++lines;

	if (payload.len) {
	  if (!stralloc_0(&payload)) {
//	    write(2,"e",1);
	    goto nomem;
	  }
	  if (base64) {
	    len=unbase64(payload.s);
	    if (len==0) {
	      buffer_putm(buffer_2,"\r\n\n",filename,":");
	      buffer_putulong(buffer_2,lines+1);
	      buffer_putsflush(buffer_2,": error: base64 decoding failed\n");
	      exit(1);
	    }
	    if (!binary) { payload.s[len]=0; ++len; }
	  } else {
	    size_t sl;
	    len=n;
	    sl=scan_ldapescape(payload.s,payload.s,&len);
	    if (sl!=payload.len-1) {
	      buffer_putm(buffer_2,"\r\n\n",filename,":");
	      buffer_putulong(buffer_2,lines+1);
	      buffer_putsflush(buffer_2,": error: LDIF de-escaping failed\n");
	      exit(1);
	    }
	    payload.s[len]=0;
	    ++len;
	  }
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
	  if ((val=mduptab_add(&classes,payload.s,len-1))==(uint32_t)-1) {
//	    write(2,"f",1);
	    goto nomem;
	  }
	} else if (tmp==dn) {
	  if ((val=add_normalized(payload.s,len))==(uint32_t)-1) {
//	    write(2,"g",1);
	    goto nomem;
	  }
	} else
	  if ((val=commit_string_bin(payload.s,len))==(uint32_t)-1) {
//	    write(2,"h",1);
	    goto nomem;
	  }
	if (tmp==(uint32_t)dn && (*l)->dn!=(uint32_t)-1) {
	  buffer_putm(buffer_2,"\r\n\n",filename,":");
	  buffer_putulong(buffer_2,recstart+1);
	  buffer_putsflush(buffer_2,": error: record has two dn entries\n");
	  exit(1);
	}
	addattribute(l,tmp,val);

	if ((*l)->dn==(uint32_t)-1) {
	  buffer_putm(buffer_2,"\r\n\n",filename,":");
	  buffer_putulong(buffer_2,recstart+1);
	  buffer_putsflush(buffer_2,": error: record without dn\n");
	  exit(1);
	}
	recstart=lines;

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
      if (!stralloc_0(&payload)) {
//	write(2,"i",1);
	goto nomem;
      }
      if (base64) {
	len=unbase64(payload.s);
	if (len==0) {
	  buffer_putm(buffer_2,"\r\n\n",filename,":");
	  buffer_putulong(buffer_2,lines+1);
	  buffer_putsflush(buffer_2,": error: base64 decoding failed\n");
	  exit(1);
	}
	if (!binary) { payload.s[len]=0; ++len; }
      } else {
	len=n;
	scan_ldapescape(payload.s,payload.s,&len);
	payload.s[len]=0;
	++len;
      }
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
      if ((val=mduptab_add(&classes,payload.s,len-1))==(uint32_t)-1) {
//	write(2,"j",1);
	goto nomem;
      }
    } else if (tmp==dn) {
      if ((val=add_normalized(payload.s,payload.len))==(uint32_t)-1) {
//	write(2,"k",1);
	goto nomem;
      }
    } else
      if ((val=commit_string_bin(payload.s,len))==(uint32_t)-1) {
//	write(2,"l",1);
	goto nomem;
      }
    if (tmp==(uint32_t)dn && (*l)->dn!=(uint32_t)-1) {
      buffer_putm(buffer_2,"\r\n\n",filename,":");
      buffer_putulong(buffer_2,recstart+1);
      buffer_putsflush(buffer_2,": error: record has two dn entries\n");
      exit(1);
    }
    addattribute(l,tmp,val);
#endif
  } while (!eof);
  if (!eof) {
    buffer_putm(buffer_2,"\r\n\n",filename,":");
    buffer_putulong(buffer_2,lines+1);
    buffer_putsflush(buffer_2,": error: parse error (maybe 2nd empty line?)\n");
    exit(1);
  }
  if ((*l)->dn==(uint32_t)-1) {
    stralloc_free(&payload);
    return 0;
  }
  if (ldif_parse_callback && ldif_parse_callback(*l)==-1) return -1;
  if ((*l)->dn==(uint32_t)-1 && ((*l)->next)) {
    struct ldaprec* m=(*l)->next;
    free((*l));
    (*l)=m;
  }
  return 0;
}

struct ldaprec *first=0;

int ldif_parse(const char* filename,off_t fromofs,struct stat* ss) {
  char buf[4096];
  int fd;
  buffer in;
  buffer* tmp;
  mstorage_init(&stringtable);
  if (ldif_addstring_callback==0) ldif_addstring_callback=addstring;
  if (filename[0]=='-' && !filename[1]) {
    tmp=buffer_0;
    fd=-1;
  } else {
    fd=open_read(filename);
    if (fd<0) return 0;		// no journal file is permissible
    if (fromofs) lseek(fd,fromofs,SEEK_SET);
    buffer_init(&in,(void*)read,fd,buf,sizeof buf);
    tmp=&in;
  }
  dn=mduptab_adds(&attributes,"dn");
  objectClass=mduptab_adds(&attributes,"objectClass");
  lines=0;
  {
    int res=parserec(tmp,&first,filename);
    if (ss) {
      fstat(fd,ss);
      /* the file size may have changed between parserec hitting EOF and
       * us calling lstat. We'll write the current file pointer position
       * to st_size */
      ss->st_size=lseek(fd,0,SEEK_CUR);
    }
    if (fd!=-1) close(fd);
    return res;
  }
}

