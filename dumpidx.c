#include <stdlib.h>
#include <libowfat/buffer.h>
#include <libowfat/mmap.h>
#include <libowfat/uint32.h>

int main(int argc,char* argv[]) {
  int verbose=0;
  size_t filelen;
  char* fn=argc<2?"data":argv[1];
  const char* map=mmap_read(fn,&filelen);
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
  if (!map) {
    buffer_puts(buffer_2,"could not open \"");
    buffer_puts(buffer_2,fn);
    buffer_puts(buffer_2,"\": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    exit(1);
  }
  buffer_puts(buffer_1,"magic: ");
  uint32_unpack(map,&magic);
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);
  buffer_putxlong(buffer_1,magic);
  buffer_puts(buffer_1,"\nattribute_count=");
  buffer_putulong(buffer_1,attribute_count);
  buffer_puts(buffer_1,"\nrecord_count=");
  buffer_putulong(buffer_1,record_count);
  buffer_puts(buffer_1,"\nindices_offset=");
  buffer_putulong(buffer_1,indices_offset);
  buffer_puts(buffer_1,"\nsize_of_string_table=");
  buffer_putulong(buffer_1,size_of_string_table);
  buffer_putsflush(buffer_1,"\n");

  buffer_puts(buffer_1,"\n\nAttributes:\n");
  /* now print some attributes */
  {
    unsigned int i;
    const char* x=map+5*4+size_of_string_table;
    for (i=0; i<attribute_count; ++i) {
      uint32 j;
      uint32_unpack(x,&j);
      buffer_puts(buffer_1,map+j);
      uint32_unpack(x+attribute_count*4,&j);
      if (j&1) buffer_puts(buffer_1," (case insensitive)");
      buffer_putsflush(buffer_1,"\n");
      x+=4;
    }
  }

  if (verbose) {
    unsigned long i;
    const char* x=map+5*4+size_of_string_table+attribute_count*8;
    buffer_puts(buffer_1,"\nRecords:\n");
    for (i=0; i<record_count; ++i) {
      uint32 j,k;
      uint32_unpack(x,&j);
      buffer_putulong(buffer_1,j);
      buffer_puts(buffer_1," attributes:\n");
      x+=8;
      buffer_puts(buffer_1,"  dn: ");
      uint32_unpack(x,&k);
      buffer_puts(buffer_1,map+k);
      buffer_puts(buffer_1,"\n  objectClass: ");
      x+=4;
      uint32_unpack(x,&k);
      buffer_puts(buffer_1,map+k);
      buffer_puts(buffer_1,"\n");
      x+=4;
      for (; j>2; --j) {
	uint32_unpack(x,&k);
	buffer_puts(buffer_1,"  ");
	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,": ");
	uint32_unpack(x+4,&k);
	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,"\n");
	x+=8;
      }
    }
  }

  buffer_puts(buffer_1,"\nIndices:\n");
  {
    uint32 ofs;
    for (ofs=indices_offset+record_count*4; ofs<(unsigned long)filelen;) {
      uint32 index_type,next,indexed_attribute;
      uint32_unpack(map+ofs,&index_type);
      uint32_unpack(map+ofs+4,&next);
      uint32_unpack(map+ofs+8,&indexed_attribute);
      buffer_puts(buffer_1,"index type: ");
      switch (index_type) {
      case 0:
	buffer_puts(buffer_1,"sorted table");
	break;
      case 1:
	buffer_puts(buffer_1,"sorted table with record pointer");
	break;
      case 2:
	buffer_puts(buffer_1,"acl data");
	break;
      case 3:
	buffer_puts(buffer_1,"hash table");
	break;
      default:
	buffer_puts(buffer_1,"unknown (");
	buffer_putulong(buffer_1,index_type);
	buffer_puts(buffer_1,")");
	break;
      }
      buffer_puts(buffer_1,"\nnext: ");
      buffer_putulong(buffer_1,next);
      if (index_type<=1 || index_type==3) {
	buffer_puts(buffer_1,"\nattribute: ");
	buffer_puts(buffer_1,map+indexed_attribute);
      }
      buffer_puts(buffer_1,"\nsize: ");
      buffer_putulong(buffer_1,(next-ofs)/1024);
      buffer_puts(buffer_1," KiB\n");
      ofs=next;
    }
  }
  buffer_flush(buffer_1);
  return 0;
}
