#define _FILE_OFFSET_BITS 64
#define MAIN

#include "ldap.h"
#include <libowfat/buffer.h>
#include <libowfat/stralloc.h>
#include <libowfat/str.h>
#include <string.h>
#include <libowfat/errmsg.h>
#include <libowfat/fmt.h>
#include <libowfat/byte.h>
#include <libowfat/mmap.h>
#include <libowfat/case.h>
#include <libowfat/uint16.h>
#include <libowfat/uint32.h>
#include <libowfat/open.h>
#include <unistd.h>
#include <assert.h>

const char Any[]="*";
const char Self[]="self";
const char Dn[]="dn";
uint32 any_ofs;

#include "acl.h"

struct assertion {
  const char* filterstring;
  struct Filter* f;
  uint32 idx;
  struct assertion* sameas;
};

struct acl {
  struct assertion subject,object;
  char* attrib;
  uint32 anum;
  char** attrs;
  unsigned short may,maynot;
  struct acl* next;
};

static unsigned long lines;
static stralloc x;

void parseerror() {
  char buf[FMT_ULONG];
  buf[fmt_ulong(buf,lines)]=0;
  die(1,"parse error in line ",buf);
}

int skipws(buffer* in) {
  char c;
  for (;;) {
    if (in->p < in->n && buffer_feed(in)<1) return 0;
    c=*buffer_peek(in);
    if (c=='\n') ++lines;
    if (c==' ' || c=='\n' || c=='\t') {
      buffer_getc(in,&c);
      continue;
    } else if (c=='#') {
      for (;;) {
	int r=buffer_getc(in,&c);
	if (r!=1) return r;
	if (c=='\n') { ++lines; break; }
      }
    } else return 1;
  }
  return 1;
}

int parseacldn(buffer* in,struct assertion* a) {
  int r,l;
  /* possible forms:
	*	-> "dn", Any
        dn:*foo -> "dn", "*foo" */
  byte_zero(a,sizeof(*a));
  a->sameas=0;
  if ((r=skipws(in))!=1) return r;
  stralloc_zero(&x);
  l=0;
  for (;;) {
    char tmp;
    r=buffer_getc(in,&tmp);
    if (r!=1) return 0;
    if (!stralloc_append(&x,&tmp)) return 0;
    if (tmp=='(') ++l;
    if (tmp==')') {
      --l;
      if (l==0) break;
    }
    if (stralloc_equals(&x,"*")) {
      a->filterstring=Any;
      return 1;
    }
    if (stralloc_equals(&x,"self")) {
      a->filterstring=Self;
      return 1;
    }
  }
  if (x.len+1<x.len) return 0;	/* catch integer overflow */
  {
    char* tmp=malloc(x.len+1);
    byte_copy(tmp,x.len,x.s);
    tmp[x.len]=0;
    a->filterstring=(const char*)tmp;
  }

  if (scan_ldapsearchfilterstring(a->filterstring,&a->f) != x.len) {
    free_ldapsearchfilter(a->f);
    return 0;
  }

  return 1;
}

int parseaclattrib(buffer* in,struct acl* a) {
  /* possible forms:
       cn,sn
       mail
       *
   */
  int r;
  a->attrib=0;
  if ((r=skipws(in))!=1) return r;

  if (in->p < in->n && buffer_feed(in)<1) return 0;
  {
    char c=*buffer_peek(in);
    if (c=='+' || c=='-') {
      a->attrib=(char*)Any;
      a->anum=1;
      return 1;
    }
  }

  r=buffer_get_new_token_sa(in,&x," \t",2);
  if (r!=1) return r;
  stralloc_chop(&x);
  if (!stralloc_0(&x)) return -1;
  if (str_equal(x.s,"*")) {
    a->attrib=(char*)Any;
    a->anum=1;
    return 1;
  }
  if (!(a->attrib=malloc(x.len))) return -1;
  memcpy(a->attrib,x.s,x.len);
  {
    unsigned int i,j;
    j=1;
    for (i=0; i<x.len; ++i)
      if (x.s[i]==',') ++j;
    a->anum=j;
  }
  return 1;
}

int parseaclpermissions(buffer* in,struct acl* a) {
  char c;
  int r;
  unsigned short* s;
  a->may=a->maynot=0; s=&a->may;
  for (;;) {
    r=buffer_getc(in,&c);
    if (r<1) return r;
    switch (c) {
    case '+': s=&a->may; break;
    case '-': s=&a->maynot; break;
    case 'r': *s|=acl_read; break;
    case 'w': *s|=acl_write; break;
    case 'a': *s|=acl_add; break;
    case 'd': *s|=acl_delete; break;
    case 'R': *s|=acl_rendn; break;
    case ' ': case '\t': case '\n': break;
    case ';': return 1;
    default: parseerror();
    }
  }
}

static int parseacl(buffer* in,struct acl* a) {
  int i,r;
  char c;
  if ((r=skipws(in))!=1) return r;
  for (i=0; i<3; ++i)
    if ((r=buffer_getc(in,&c))!=1 || c!="acl"[i]) {
      if (r==0 && i==0) return 0;
      parseerror();
    }
  if ((r=parseacldn(in,&a->subject))!=1) return r;
  if ((r=parseacldn(in,&a->object))!=1) return r;
  if ((r=parseaclattrib(in,a))!=1) return r;
  if ((r=parseaclpermissions(in,a))!=1) return r;
  a->next=0;
  return 1;
}

static void fold(struct assertion* a,struct assertion* b) {
  if (a==b) return;
#if 0
  printf("fold \"%s\" \"%s\"\n",a->filterstring,b->filterstring);
#endif
  if (b->sameas || a->sameas) return;
  if (!strcmp(a->filterstring,b->filterstring)) {
    a->sameas=b;
#if 0
    printf("  -> folded!\n");
#endif
  }
}

static void optimize(struct acl* a) {
  struct acl* origa=a;
  struct acl* b;
  for (; a; a=a->next)
    for (b=origa; b!=a; b=b->next) {
      fold(&a->subject,&b->subject);
      fold(&a->object,&b->object);
      fold(&a->subject,&b->object);
      fold(&b->subject,&a->object);
      fold(&b->subject,&b->object);
      fold(&a->subject,&a->object);
    }

#if 0
  for (a=origa; a; a=a->next) {
    if (a->subject.sameas && a->subject.sameas->sameas)
      puts("ARGH 1!");
    if (a->object.sameas && a->object.sameas->sameas)
      puts("ARGH 2!");
  }
#endif
}

static struct acl* root;

int readacls(const char* filename) {
  buffer b;
  struct acl **next, a;
  int r;
  root=0; next=&root;
  if (buffer_mmapread(&b,filename)==-1) return -1;
  while ((r=parseacl(&b,&a))==1) {
    *next=malloc(sizeof(struct acl));
    if (!*next) diesys(1,"malloc");
    byte_copy(*next,sizeof(a),&a);
//    **next=a;
    next=&(*next)->next;
    if (r==0) break;
  }
  if (r==-1) parseerror();

  buffer_close(&b);
  optimize(root);

  return 0;
}

int marshalfilter(stralloc* x,struct assertion* a) {
  if (a->filterstring==Self)
    return stralloc_catb(x,Self,5);
  if (a->filterstring==Any)
    return stralloc_catb(x,Any,2);
  else {
    char* tmp;
    unsigned long l=fmt_ldapsearchfilter(0,a->f);
    tmp=alloca(l+10);	// you never know
    if (fmt_ldapsearchfilter(tmp,a->f)!=l) {
      buffer_putsflush(buffer_2,"internal error!\n");
      exit(1);
    }
    return stralloc_catb(x,tmp,l);
  }
}

int marshal(const char* map,size_t filelen,const char* filename) {
  size_t filters,acls,i,j,k;
  size_t filter_offset; //,acl_offset;
  struct acl* a;
  uint32* F,* A;
  uint32 attribute_count;
  uint32 attrtab;
  static stralloc x,y;
  int fd=open_append(filename);

  if (fd==-1)
    diesys(1,"could not open file `",filename,"' for writing");

  stralloc_copys(&x,"");
  stralloc_copys(&y,"");
  filters=acls=0;
  for (a=root; a; a=a->next) {
    ++acls;
    if (!a->subject.sameas) {
      a->subject.idx=filters;
      ++filters;
    }
    if (!a->object.sameas) {
      a->object.idx=filters;
      ++filters;
    }
  }

  buffer_putulong(buffer_1,acls);
  buffer_puts(buffer_1," ACLs with ");
  buffer_putulong(buffer_1,filters);
  buffer_putsflush(buffer_1," filters.\n");

  if (acls==0) {
    buffer_putsflush(buffer_1,"No ACLs defined. We are done here.\n");
    exit(0);
  }

  F=malloc(sizeof(*F)*(filters+1));
  if (!F) goto nomem;

  filter_offset=filelen+(filters+4)*sizeof(*F);	/* 2 uints for index header, 1 uint filters_count, then filter_count+1 uint32 in F */

  i=0;
  x.len=0;
  for (a=root; a; a=a->next) {
    if (!a->subject.sameas) {
      F[i]=x.len+filter_offset;
      ++i;
      if (!marshalfilter(&x,&a->subject)) {
nomem:
	buffer_putsflush(buffer_2,"out of memory!\n");
	exit(1);
      }
//      printf("marshalled \"%s\" to %ld\n",a->subject.filterstring,F[i-1]);
    }
    if (!a->object.sameas) {
      F[i]=x.len+filter_offset;
      ++i;
      if (!marshalfilter(&x,&a->object)) goto nomem;
//      printf("marshalled \"%s\" to %ld\n",a->object.filterstring,F[i-1]);
    }
  }
  attribute_count=uint32_read(map+4);
  attrtab=5*4+uint32_read(map+16);

  if (attribute_count == 0) {
    buffer_putsflush(buffer_2,"malformed data file (attribute_count zero!?)\n");
    exit(1);
  }
  /* here we need to have each attribute mentioned in any ACL
   * point to the proper offset in the data file.  But what if an ACL
   * mentions an attribute that never occurs in any of the records?  In
   * that case, we insert a small "string table" between the filters and
   * the ACLs.  To make it possible to skip over it, the offset table of
   * the filters has one more element, which points to the start of the
   * ACLs. */
  {
    int anyused=0;

    for (a=root; a; a=a->next) {
      unsigned int l=0;
//      printf("a->anum = %lu\nsizeof(*a->attrs) = %lu\n",a->anum,sizeof(*a->attrs));
      if (!(a->attrs=calloc(a->anum,sizeof(*a->attrs))))
	goto nomem;
      a->attrs[l]=a->attrib; ++l;
      if (a->attrib!=Any) {
	for (k=0; a->attrib[k]; ++k)
	  if (a->attrib[k]==',') {
	    a->attrib[k]=0;
	    a->attrs[l]=a->attrib+k+1;
	  }
#ifndef __dietlibc__
	assert(l==a->anum);	// this is for the benefit of clang's static analyzer
#endif
	for (k=0; k<a->anum; ++k) {
	  int found=0;
	  for (j=0; j<attribute_count; ++j) {
	    if (!strcmp(map+uint32_read(map+attrtab+j*4),a->attrs[k])) {
	      a->attrs[k]=(char*)map+uint32_read(map+attrtab+j*4);
	      found=1;
	      break;
	    }
	  }
	  if (!found) {
	    /* warning: evil kludge ahead!  We assume that the sum of the
	    * lengths of the new attributes plus the ACLs is smaller than
	    * the address where mmap mapped the file. */
	    char* tmp=a->attrs[k];
  //	  buffer_putmflush(buffer_1,"adding attribute ",a->attrs[k],"\n");
	    a->attrs[k]=(char*)map+filelen+
			2*4+		/* index_type and next */
			(filters+2)*4+	/* filters_count plus (filter_count+1)*uint32 */
			x.len;
	    if (!stralloc_catb(&x,tmp,strlen(tmp)+1)) goto nomem;
	  }
	}
      } else anyused=1;
    }
    if (anyused) {
      any_ofs=filelen+2*4+(filters+2)*4+x.len;
//      printf("filelen is %d, filters is %d, x.len is %d -> anyofs is %d\n",filelen,filters,x.len,any_ofs);
      if (!stralloc_catb(&x,Any,2)) goto nomem;
    }
  }

  /* 32-bit align */
  {
    unsigned int align=(-(x.len&3))&3;
    if (!stralloc_catb(&x,"\0\0\0",align)) goto nomem;
  }
  F[i]=x.len+filter_offset;

  /* now the ACLs */

  A=malloc(sizeof(*A)*acls);
  if (!A) goto nomem;
//  acl_offset=F[i]+(acls+1)*sizeof(*A);

  i=0;
  for (a=root; a; a=a->next) {
    char tmp[4];
    unsigned int j;
    A[i]=y.len; ++i;
    if (!stralloc_readyplus(&y,12)) goto nomem;
    if (a->subject.sameas)
      uint32_pack(tmp,a->subject.sameas->idx);
    else
      uint32_pack(tmp,a->subject.idx);
    stralloc_catb(&y,tmp,4);
    if (a->object.sameas)
      uint32_pack(tmp,a->object.sameas->idx);
    else
      uint32_pack(tmp,a->object.idx);
    stralloc_catb(&y,tmp,4);
    uint16_pack(tmp,a->may);
    stralloc_catb(&y,tmp,2);
    uint16_pack(tmp,a->maynot);
    stralloc_catb(&y,tmp,2);
    if (a->attrib==Any) {
      uint32_pack(tmp,any_ofs);
      if (!stralloc_catb(&y,tmp,4)) goto nomem;
    } else {
      for (j=0; j<a->anum; ++j) {
	if (a->attrs[j]==Any)
	buffer_putmflush(buffer_1,a->attrs[j],"\n");
	uint32_pack(tmp,a->attrs[j]-map);
	if (!stralloc_catb(&y,tmp,4)) goto nomem;
      }
    }
    uint32_pack(tmp,0);
    if (!stralloc_catb(&y,tmp,4)) goto nomem;
  }

  /* 32-bit align */
  {
    unsigned int align=(-(y.len&3))&3;
    if (!stralloc_catb(&y,"\0\0\0",align)) goto nomem;
  }

  {
    char tmp[8];
    unsigned long i;
    uint32 fixup;
    /* write index header:
     *   uint32 index_type (2 in this case);
     *   uint32 offset_of_next_header; */
    uint32_pack(tmp,2);
    uint32_pack(tmp+4,filelen+
		      8+		/* index header */
		      4+		/* uint32 filters_count; */
		      4*(filters+1)+	/* uint32 offsets_to_filters_in_scan_ldapsearchfilter_format[filter_count+1]; */
		      x.len+		/* marshalled filters */
		      4+		/* uint32 acl_count */
		      4*acls+		/* uint32 offsets_to_acls[acl_count]; */
		      y.len);		/* marshalled acls */
    if (write(fd,tmp,8)!=8) {
shortwrite:
      free(A); free(F);
      ftruncate(fd,filelen);
      close(fd);
      diesys(1,"short write");
    }
    /* uint32 filter_count */
    uint32_pack(tmp,filters);
    if (write(fd,tmp,4)!=4) goto shortwrite;
    /* uint32 offsets_to_filters_in_scan_ldapsearchfilter_format[filter_count+1]; */
    for (i=0; i<filters+1; ++i)
      uint32_pack((char*)(F+i),F[i]);
    if (write(fd,F,(filters+1)*4) != (ssize_t)((filters+1)*4)) goto shortwrite;
    /* write marshalled filter data */
    if (write(fd,x.s,x.len) != (ssize_t)x.len) goto shortwrite;
    /* uint32 acl_count */
    uint32_pack(tmp,acls);
    if (write(fd,tmp,4)!=4) goto shortwrite;
    /* uint32 offsets_to_acls[acl_count] */
    fixup=lseek(fd,0,SEEK_CUR)+acls*4;
    for (i=0; i<acls; ++i)
      uint32_pack((char*)(A+i),A[i]+fixup);
    if (write(fd,A,acls*4) != (ssize_t)(acls*4)) goto shortwrite;
    /* write marshalled acl data */
    if (write(fd,y.s,y.len) != (ssize_t)y.len) goto shortwrite;
  }
  free(A); free(F);
  close(fd);
  return 0;
}

#ifdef MAIN
int main(int argc,char* argv[]) {
  size_t filelen;
  char* filename=argc>1?argv[1]:"data";
  const char* map=mmap_read(filename,&filelen);

  if (!map) {
    buffer_putmflush(buffer_2,"Could not open ",filename,"\n");
    return 0;
  }

  if (filelen<5*4 || uint32_read(map)!=0xfefe1da9) {
    buffer_putsflush(buffer_2,"not a valid tinyldap data file!\n");
    return 0;
  }

  if (readacls("acls")==-1) die(1,"readacls failed");
//  acl_offsets(map,filelen);

  marshal(map,filelen,filename);
  return 0;
}
#endif

