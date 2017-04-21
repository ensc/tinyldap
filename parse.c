/* This is just the main() for "parse".  The actual parser is in
 * ldif_parse.c */
#define _FILE_OFFSET_BITS 64
#include <alloca.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <stdlib.h>
#include <string.h>
#include <libowfat/buffer.h>
#include "ldif.h"
#include "mduptab.h"
#include <libowfat/uint32.h>
#include <libowfat/byte.h>
#include <libowfat/fmt.h>
#include <libowfat/errmsg.h>

/* these are defined in ldif_parse.c.
 * We extern them here so we can initialize them.
 * This was not necessary until I reworked mstorage_t to support
 * persistence via a file descriptor, which needs to be -1 and not 0 if
 * unused. */
extern mduptab_t attributes,classes;
  /* we do a minor optimization by saving the strings of names of
   * attributes and objectClass values only once.  mduptab_t is the data
   * structure used for this, see mduptab.h */
// extern mstorage_t stringtable;
  /* this is a giant string table where all the strings (keys and
   * values) of the data are written to.  This is actually the memory
   * mapped destination file. */
extern int (*ldif_parse_callback)(struct ldaprec* l);
  /* ldif_parse.c contains the actual ldif parser.  It reads from a
   * buffer (see libowfat, buffer.h) and creates a linked list of
   * entries.  This is unnecessarily wasteful, so I added the above
   * callback, which is called after each record.  If the callback
   * is non-NULL and returns 1 when called with the record the parser
   * just read in, the parser will assume the record has been stored
   * somewhere else and not create a linked list but overwrite the same
   * record in memory.  This saves space and overhead.  If we need to
   * work on even larger files, this could even be reworked to be a
   * persistent mmapped temp file. */

/* parse exp.ldif and write binary representation to "data".
 * please read "FORMAT" for a description of the file format */

/* please note that tinyldap separates the data and the index although
 * they are in the same file.  This program only creates the binary
 * representation, the actual indices are created by addindex. */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern unsigned long mstorage_increment;

static unsigned long outofs;
static unsigned long recofs;

/* Records are stored with a variable length externally, see FORMAT.
 * We need to store the records and a table of the offsets of the
 * records inside the data file in the data file.  These data structures
 * hold this data: */
// mstorage_t records;
unsigned long offset_classes,record_count;

buffer outbuf,rbuf;

static void printstats() {
  buffer_puts(buffer_2,"\r");
  buffer_putulong(buffer_2,record_count);
  buffer_puts(buffer_2," records parsed, ");
  buffer_putulong(buffer_2,outofs/1024);
  buffer_puts(buffer_2,"k strings, ");
  buffer_putulong(buffer_2,recofs/1024);
  buffer_putsflush(buffer_2,"k records.        ");
}

uint32 my_addstring(const char* s,unsigned long len) {
  uint32 tmp=outofs;
  if (buffer_put(&outbuf,s,len)) return -1;
  outofs+=len;
  return tmp;
}

int ldif_callback(struct ldaprec* l) {
  char x[8];	/* temp buf for endianness conversion */
  unsigned int i;
//  uint32 ofs;
  uint32 oc=(uint32)-1;	/* value of the first objectClass */

  if (!l->n) return 0;
  for (i=0; i<l->n; ++i) {
    if (l->a[i].name==objectClass) {
      oc=l->a[i].value;
      l->a[i].value=-1;
      break;
    }
  }
  if (oc==(uint32)-1) {
    extern long lines;
    buffer_puts(buffer_1,"ignoring record without objectClass... (line ");
    buffer_putulong(buffer_1,lines);
    buffer_putsflush(buffer_1,")\n");
    return 0;
  }

  uint32_pack(x,l->n+1);
  uint32_pack(x+4,0);

//  ofs=recofs;
  if (buffer_put(&rbuf,x,8)) return -1;
  recofs+=8;
//  if ((ofs=mstorage_add(&records,x,8))==(uint32)-1) return -1;

  uint32_pack(x,l->dn);
  uint32_pack(x+4,oc);

  if (buffer_put(&rbuf,x,8)) return -1;
  recofs+=8;
//  if (mstorage_add(&records,x,8)==-1) return -1;

  for (i=0; i<l->n; ++i) {
    if (l->a[i].name==objectClass && l->a[i].value==(uint32)-1) continue;
    uint32_pack(x,l->a[i].name);
    uint32_pack(x+4,l->a[i].value);
    if (buffer_put(&rbuf,x,8)) return -1;
    recofs+=8;
//    if (mstorage_add(&records,x,8)==-1) return -1;
  }
//  uint32_pack(x,ofs);
//  if (mstorage_add(&record_offsets,x,4)==-1) return -1;
  ++record_count;
  if ((record_count%10000)==0)
    printstats();
  return 0;
}

extern uint32 (*ldif_addstring_callback)(const char* s,unsigned long len);

int main(int argc,char* argv[]) {
  char buf[64*1024];
  char recbuf[8*1024];
  int fd,rfd;
  long len;
  char* destname=argc<3?"data":argv[2];
  char* tempname;
  unsigned long size_of_string_table,indices_offset;
//  long offset_stringtable;
  char* map;
  uint32 attrofs,classofs;

  ldif_addstring_callback=my_addstring;

  tempname=alloca(strlen(destname)+10);
//  mstorage_init(&record_offsets);

  rfd=fmt_str(tempname,destname);
  rfd+=fmt_str(tempname+rfd,".rec");
  tempname[rfd]=0;
  if ((rfd=open(tempname,O_RDWR|O_CREAT|O_TRUNC,0600))<0) {
    buffer_puts(buffer_2,"could not create temp file ");
    buffer_puts(buffer_2,tempname);
    goto derrout2;
  }

  buffer_init(&rbuf,(void*)write,rfd,recbuf,sizeof recbuf);

  ldif_parse_callback=ldif_callback;

  if ((fd=open(destname,O_RDWR|O_CREAT|O_TRUNC,0600))<0) {
    buffer_puts(buffer_2,"could not create destination data file ");
    buffer_puts(buffer_2,destname);
derrout2:
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    return 1;
  }

  buffer_init(&outbuf,(void*)write,fd,buf,sizeof buf);

  mduptab_init(&attributes);
  mduptab_init(&classes);

  {
    char dummy[5*4];
    if (buffer_put(&outbuf,dummy,5*4))
writeerror:
      diesys(1,"write error (disk full?)");
    outofs=5*4;
    recofs=0;
  }

//  if ((mduptab_adds(&attributes,"*"))<0)
//    die(1,"out of memory");

  ldif_parse(argc<2?"exp.ldif":argv[1],0,0);
  if (!first)
    die(1,"usage: parse [src-ldif-filename] [dest-bin-filename]\n");

  printstats();
  buffer_putsflush(buffer_2,"DONE!\n");

  if (buffer_flush(&rbuf)) goto writeerror;

  /* now we have to add the classes and attributes to the "string table".
     problem is: we already wrote the offsets within the local tables to
     the record table, so we need to do some relocation */

  /* first, add the strings */
  attrofs=outofs;
  if (buffer_put(&outbuf,attributes.strings.root,attributes.strings.used))
    goto writeerror;
  outofs+=attributes.strings.used;
  classofs=outofs;
  if (buffer_put(&outbuf,classes.strings.root,classes.strings.used))
    goto writeerror;
  outofs+=classes.strings.used;

  if (outofs&3) {	/* round up to 32-bit boundary */
    if (buffer_put(&outbuf,"\x00\x00\x00",4-(outofs&3))) goto writeerror;
    outofs+=4-(outofs&3);
  }
  buffer_flush(&outbuf);

  size_of_string_table=outofs-5*4;
  size_of_string_table=(size_of_string_table+3)&-4;	/* round up to 32 bits */
  /* first find out how much space we need */

  {
    uint32 i,n;
    char convbuf[4];
    n=attributes.table.used/sizeof(long);
    for (i=0; i<n; ++i) {
      uint32_pack(convbuf,((long*)attributes.table.root)[i]+attrofs);
      if (buffer_put(&outbuf,convbuf,4)) goto writeerror;
      outofs+=4;
    }
    byte_zero(convbuf,4);
    for (i=0; i<n; ++i) {
      if (buffer_put(&outbuf,convbuf,4)) goto writeerror;
      outofs+=4;
    }
  }

  {
    uint32 i;
    uint32* offsets=malloc(sizeof(uint32)*record_count);

    if (!offsets) die(1,"out of memory");

    buffer_flush(&rbuf);
    if (lseek(rfd,0,SEEK_SET)!=0) diesys(1,"lseek failed");
    buffer_init(&rbuf,(void*)read,rfd,recbuf,sizeof recbuf);

    for (i=0; i<record_count; ++i) {
      char convbuf[8];
      uint32 j,n;
      offsets[i]=outofs;
      if (buffer_getn(&rbuf,convbuf,8)!=8) die(1,"short read");
      n=uint32_read(convbuf);
      if (buffer_put(&outbuf,convbuf,8)) diesys(1,"short write (disk full?)");
      outofs+=8;
      for (j=1; j<n; ++j) {
	if (buffer_getn(&rbuf,convbuf,8)!=8) die(1,"short read");
	if (j==1)
	  uint32_pack(convbuf+4,uint32_read(convbuf+4)+classofs);
	else {
	  uint32 attr;
	  uint32_pack(convbuf,(attr=uint32_read(convbuf))+attrofs);
	  if (attr==objectClass)
	    uint32_pack(convbuf+4,uint32_read(convbuf+4)+classofs);
	}
	if (buffer_put(&outbuf,convbuf,8)) diesys(1,"short write (disk full?)");
	outofs+=8;
      }
    }
    len = outofs;

    indices_offset=len;
    // len+=record_count*4;	// not actually needed after this

    if (buffer_put(&outbuf,(char*)offsets,sizeof(uint32)*record_count)) diesys(1,"short write (disk full?)");
    free(offsets);
  }

  /* done!  we don't create any indices for now. */

  if (buffer_flush(&outbuf)) goto writeerror;
//  munmap(stringtable.root,stringtable.mapped);
//  ftruncate(fd,len);
  if ((map=mmap(0,5*4,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0))==MAP_FAILED) {
    buffer_putsflush(buffer_2,"could not mmap destination data file!\n");
    unlink(destname);
    unlink(tempname);
    return 1;
  }
  uint32_pack(map    ,0xfefe1da9);		/* magic */
  uint32_pack(map+1*4,attributes.table.used/sizeof(long)); /* attribute_count */
  uint32_pack(map+2*4,record_count);		/* record_count */
  uint32_pack(map+3*4,indices_offset);		/* indices_offset */
  uint32_pack(map+4*4,size_of_string_table);	/* size_of_string_table */

//  size_of_string_table=stringtable.used+classes.strings.used+attributes.strings.used;
//  offset_stringtable=5*4;
  offset_classes=outofs;

  munmap(map,5*4);
  close(fd);
  close(rfd);
  unlink(tempname);
  return 0;
}
