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

extern mduptab_t attributes,classes;
extern mstorage_t stringtable;

/* parse exp.ldif and write binary representation to "data".
 * please read "FORMAT" for a description of the file format */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

void dumprec(struct ldaprec* l) {
  int i;
  if (l->dn>=0) {
    buffer_puts(buffer_1,"dn: ");
    buffer_puts(buffer_1,stringtable.root+l->dn);
    buffer_puts(buffer_1,"\n");
  } else
    buffer_puts(buffer_1,"no dn?!\n");
  for (i=0; i<l->n; ++i) {
    buffer_puts(buffer_1,attributes.strings.root+l->a[i].name);
    buffer_puts(buffer_1,": ");
    if (l->a[i].name==objectClass)
      buffer_puts(buffer_1,classes.strings.root+l->a[i].value);
    else
      buffer_puts(buffer_1,stringtable.root+l->a[i].value);
    buffer_puts(buffer_1,"\n");
  }
  buffer_putsflush(buffer_1,"\n");
}

int main(int argc,char* argv[]) {
  int fd;
  long len;
  unsigned long size_of_string_table,indices_offset,record_count;
  long offset_stringtable,offset_classes,offset_attributes;
  char* map,* dest;
  ldif_parse(argc<2?"exp.ldif":argv[1]);
  if (!first) {
    buffer_putsflush(buffer_2,"no data?!");
    return 1;
  }

  size_of_string_table=stringtable.used+classes.strings.used+attributes.strings.used;
  size_of_string_table=(size_of_string_table+3)&-4;	/* round up to 32 bits */
  /* first find out how much space we need */
  len = 5*sizeof(uint32_t);  /* magic plus four counts */
  len += size_of_string_table;   /* size of string table */
  len += attributes.table.used/sizeof(long)*8;   /* attribute_names plus attribute_flags */

//  fdprintf(2,"offsets of records: %lu\n",len);

  /* now for the hard part: the records */
  {
    struct ldaprec* x=first;
    record_count=0;
    while (x) {
      int oc=0,i;
//      long old=len;
      /* we add 8 for the <length-in-uint32_t,0> pair and we substract 8
       * for the two saved pointers ("dn" and "objectClass") */
      if (x->dn>=0) len+=8; else {
	if (x->n==0 && x->next==0) break;
	buffer_putsflush(buffer_2,"record without dn?!\n");
	dumprec(x);
	return 1;
      }
      for (i=0; i<x->n; ++i) {
	len+=8;
	if (x->a[i].name==objectClass) oc=1;
      }
      if (!oc) {
	buffer_puts(buffer_2,"record \"");
	buffer_puts(buffer_2,x->dn+stringtable.root);
	buffer_putsflush(buffer_2,"\" has no objectClass?!\n");
	dumprec(x);
	return 1;
      }
      ++record_count;
//      fdprintf(2,"considering record \"%s\": length %d\n",x->dn+stringtable.root,len-old);
      x=x->next;
    }
  }
//  fdprintf(2,"offsets of indices: %lu\n",len);
  indices_offset=len;
  len+=record_count*4;
  /* done!  we don't create any indices for now. */
  if ((fd=open("data",O_RDWR|O_CREAT|O_TRUNC,0600))<0) {
    buffer_putsflush(buffer_2,"could not create data");
    return 1;
  }
  ftruncate(fd,len);
  if ((map=mmap(0,len,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0))==MAP_FAILED) {
    buffer_putsflush(buffer_2,"could not mmap data!\n");
    unlink("data");
    return 1;
  }
  uint32_pack(map    ,0xfefe1da9);		/* magic */
  uint32_pack(map+1*4,attributes.table.used/sizeof(long)); /* attribute_count */
  uint32_pack(map+2*4,record_count);		/* record_count */
  uint32_pack(map+3*4,indices_offset);		/* indices_offset */
  uint32_pack(map+4*4,size_of_string_table);	/* size_of_string_table */

//  size_of_string_table=stringtable.used+classes.strings.used+attributes.strings.used;
  offset_stringtable=5*4;
  offset_classes=offset_stringtable+stringtable.used;
  offset_attributes=offset_classes+classes.strings.used;
  byte_copy(map+offset_stringtable,stringtable.used,stringtable.root);
  byte_copy(map+offset_classes,classes.strings.used,classes.strings.root);
  byte_copy(map+offset_attributes,attributes.strings.used,attributes.strings.root);
//  fdprintf(2,"offset_classes=%lu, offset_attributes=%lu, attributes=%lu\n",
//	   offset_classes,offset_attributes,attributes.strings.used);
  dest=map+offset_stringtable+size_of_string_table;
  {
    unsigned long i;
    for (i=0; i<attributes.table.used/sizeof(long); ++i) {
#if 0
      fdprintf(2,"writing at %x: attribute %lu (%s)\n",dest+i-map,
	       ((long*)attributes.table.root)[i],attributes.strings.root+((long*)attributes.table.root)[i]);
#endif
      uint32_pack(dest+i*4,((long*)attributes.table.root)[i]+offset_attributes);
    }
    i=attributes.table.used/sizeof(long)*4;
    dest+=i;
    byte_zero(dest,i);
    dest+=i;
  }
//  fdprintf(2,"actual offset before records: %lu\n",dest-map);
  /* now the records */
  {
    struct ldaprec* x=first;
    uint32_t* record_offsets=alloca(4*record_count);
    uint32_t cur=0;
    while (x) {
      int i=x->n+1;
      record_offsets[cur]=dest-map; ++cur;
      uint32_pack(dest,i); uint32_pack(dest+4,0); dest+=8;
      uint32_pack(dest,x->dn+offset_stringtable);
      for (i=0; i<x->n; ++i) {
	if (x->a[i].name==objectClass) {
	  uint32_pack(dest+4,x->a[i].value+offset_classes);
	  x->a[i].name=-1;
	  break;
	}
      }
      dest+=8;
      for (i=0; i<x->n; ++i) {
	if (x->a[i].name>=0) {
	  uint32_pack(dest,x->a[i].name+offset_attributes);
	  if (x->a[i].name==objectClass)
	    uint32_pack(dest+4,x->a[i].value+offset_classes);
	  else
	    uint32_pack(dest+4,x->a[i].value+offset_stringtable);
	  dest+=8;
	}
      }
      x=x->next;
    }
//    fdprintf(2,"actual offset of record_index: %lu\n",dest-map);
    /* now the record_index */
    for (cur=0; cur<record_count; ++cur) {
      uint32_pack(dest,record_offsets[cur]);
      dest+=4;
    }
  }
  munmap(map,len);
  close(fd);
  return 0;
}
