/* This is just the main() for "parse".  The actual parser is in
 * ldif_parse.c */
#include <alloca.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <stdlib.h>
#include "buffer.h"
#include "ldif.h"
#include "mduptab.h"
#include "uint32.h"
#include "byte.h"
#include "fmt.h"

/* these are defined in ldif_parse.c.
 * We extern them here so we can initialize them.
 * This was not necessary until I reworked mstorage_t to support
 * persistence via a file descriptor, which needs to be -1 and not 0 if
 * unused. */
extern mduptab_t attributes,classes;
  /* we do a minor optimization by saving the strings of names of
   * attributes and objectClass values only once.  mduptab_t is the data
   * structure used for this, see mduptab.h */
extern mstorage_t stringtable;
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

/* for debugging and error messages */
/* ldaprec is the struct used by ldif_parse.c */
void dumprec(struct ldaprec* l) {
  int i;
  if (l->dn>=0) {
    buffer_puts(buffer_1,"dn: ");
    buffer_puts(buffer_1,stringtable.root+l->dn);
    buffer_puts(buffer_1,"\n");
  } else
    buffer_puts(buffer_1,"no dn?!\n");
  for (i=0; i<l->n; ++i) {
    buffer_puts(buffer_1,attributes.Strings->root+l->a[i].name);
    buffer_puts(buffer_1,": ");
    if (l->a[i].name==objectClass)
      buffer_puts(buffer_1,classes.Strings->root+l->a[i].value);
    else
      buffer_puts(buffer_1,stringtable.root+l->a[i].value);
    buffer_puts(buffer_1,"\n");
  }
  buffer_putsflush(buffer_1,"\n");
}

/* Records are stored with a variable length externally, see FORMAT.
 * We need to store the records and a table of the offsets of the
 * records inside the data file in the data file.  These data structures
 * hold this data: */
mstorage_t record_offsets;
mstorage_t records;
unsigned long offset_classes,record_count;
  /* record_count is just a convenience, the same value is also visible
   * as record_offsets.used/4 */

static void printstats() {
  buffer_puts(buffer_2,"\r");
  buffer_putulong(buffer_2,record_count);
  buffer_puts(buffer_2," records parsed, ");
  buffer_putulong(buffer_2,stringtable.used/1024);
  buffer_puts(buffer_2,"k strings, ");
  buffer_putulong(buffer_2,records.used/1024);
  buffer_puts(buffer_2,"k records, ");
  buffer_putulong(buffer_2,record_offsets.used/1024);
  buffer_putsflush(buffer_2,"k record offsets.        ");
}

int ldif_callback(struct ldaprec* l) {
  char x[8];	/* temp buf for endianness conversion */
  int i;
  uint32 ofs;
  uint32 oc;	/* value of the first objectClass */
  int found;

  if (!l->n) return 0;
  found=0;
  for (i=0; i<l->n; ++i) {
    if (l->a[i].name==objectClass) {
      oc=l->a[i].value;
      l->a[i].value=-1;
      found=1;
      break;
    }
  }
  if (!found) {
    buffer_putsflush(buffer_1,"ignoring record without objectClass...\n");
    dumprec(l);
    return 0;
  }

  uint32_pack(x,l->n+1);
  uint32_pack(x+4,0);
  if ((ofs=mstorage_add(&records,x,8))==(uint32)-1) return -1;
  uint32_pack(x,l->dn);
  uint32_pack(x+4,oc);

  if (mstorage_add(&records,x,8)==-1) return -1;
  for (i=0; i<l->n; ++i) {
    if (l->a[i].name==objectClass && l->a[i].value==-1) continue;
    uint32_pack(x,l->a[i].name);
    uint32_pack(x+4,l->a[i].value);
    if (mstorage_add(&records,x,8)==-1) return -1;
  }
  uint32_pack(x,ofs);
  if (mstorage_add(&record_offsets,x,4)==-1) return -1;
  ++record_count;
  if ((record_count%10000)==0)
    printstats();
  return 0;
}

int main(int argc,char* argv[]) {
  int fd,rfd;
  long len;
  char* destname=argc<3?"data":argv[2];
  char* tempname;
  unsigned long size_of_string_table,indices_offset;
  long offset_stringtable;
  char* map,* dest;

  tempname=alloca(strlen(destname)+10);
  mstorage_init(&record_offsets);

  rfd=fmt_str(tempname,destname);
  rfd+=fmt_str(tempname+rfd,".rec");
  tempname[rfd]=0;
  if ((rfd=open(tempname,O_RDWR|O_CREAT|O_TRUNC,0600))<0) {
    buffer_puts(buffer_2,"could not create temp file ");
temperrout:
    buffer_puts(buffer_2,tempname);
    goto derrout2;
  }
  if (mstorage_init_persistent(&records,rfd)==-1) {
    buffer_puts(buffer_2,"mstorage_init_persistent: error mmapping ");
    goto temperrout;
  }

//  mstorage_init(&records);
  ldif_parse_callback=ldif_callback;

  if ((fd=open(destname,O_RDWR|O_CREAT|O_TRUNC,0600))<0) {
    buffer_puts(buffer_2,"could not create destination data file ");
derrout:
    buffer_puts(buffer_2,destname);
derrout2:
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    return 1;
  }
  if (mstorage_init_persistent(&stringtable,fd)==-1) {
    buffer_puts(buffer_2,"mstorage_init_persistent: error mmapping ");
    goto derrout;
  }
  mduptab_init_reuse(&attributes,&stringtable);
  mduptab_init_reuse(&classes,&stringtable);

  {
    char dummy[5*4];
    mstorage_add(&stringtable,dummy,5*4);
  }

  ldif_parse(argc<2?"exp.ldif":argv[1]);
  if (!first) {
    buffer_putsflush(buffer_2,"usage: parse [src-ldif-filename] [dest-bin-filename]\n");
    return 1;
  }

  printstats();
  buffer_putsflush(buffer_2,"DONE!\n");

  size_of_string_table=stringtable.used-5*4;
  size_of_string_table=(size_of_string_table+3)&-4;	/* round up to 32 bits */
  /* first find out how much space we need */
  len = 5*sizeof(uint32_t);  /* magic plus four counts */
  len += size_of_string_table;   /* size of string table */
  len += attributes.table.used/sizeof(long)*8;   /* attribute_names plus attribute_flags */

//  fdprintf(2,"offsets of records: %lu\n",len);

  len += records.used;

//  fdprintf(2,"offsets of indices: %lu\n",len);
  indices_offset=len;
  len+=record_count*4;
  /* done!  we don't create any indices for now. */

  munmap(stringtable.root,stringtable.mapped);
  ftruncate(fd,len);
  if ((map=mmap(0,len,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0))==MAP_FAILED) {
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
  offset_stringtable=5*4;
  offset_classes=stringtable.used;

  dest=map+offset_stringtable+size_of_string_table;
  {
    unsigned long i;
    for (i=0; i<attributes.table.used/sizeof(long); ++i) {
      uint32_pack(dest+i*4,((long*)attributes.table.root)[i]);
    }
    i=attributes.table.used/sizeof(long)*4;
    dest+=i;
    byte_zero(dest,i);
    dest+=i;
  }

  {
    char* x;
    unsigned long i;
    uint32 addme=dest-map;
    byte_copy(dest,records.used,records.root);
    x=record_offsets.root;
    dest+=records.used;
    for (i=0; i<record_count; ++i)
      uint32_pack(dest+4*i,uint32_read(x+4*i)+addme);
  }

  munmap(map,len);
  close(fd);
  close(rfd);
  unlink(tempname);
  return 0;
}
