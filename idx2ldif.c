#include "buffer.h"
#include "mmap.h"
#include "uint32.h"

int main() {
  int verbose=1;
  long filelen;
  char* map=mmap_read("data",&filelen);
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
  uint32_unpack(map,&magic);
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);

  if (verbose) {
    unsigned long i;
    char* x=map+5*4+size_of_string_table+attribute_count*8;
    for (i=0; i<record_count; ++i) {
      uint32 j,k;
      uint32_unpack(x,&j);

      x+=8;
      buffer_puts(buffer_1,"dn: ");
      uint32_unpack(x,&k);
      buffer_puts(buffer_1,map+k);
      buffer_puts(buffer_1,"\nobjectClass: ");
      x+=4;
      uint32_unpack(x,&k);
      buffer_puts(buffer_1,map+k);
      buffer_puts(buffer_1,"\n");
      x+=4;
      for (; j>2; --j) {
	uint32_unpack(x,&k);
	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,": ");
	uint32_unpack(x+4,&k);
	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,"\n");
	x+=8;
      }
      buffer_puts(buffer_1,"\n");
    }
  }
  buffer_flush(buffer_1);

  return 0;
}
