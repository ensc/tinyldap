#include <alloca.h>
#include <ctype.h>
#include <stdlib.h>
#include "buffer.h"
#include "mmap.h"
#include "uint32.h"
#include "bstr.h"
#include "textcode.h"

static void dumpbstr(const char* c) {
  int printable=1;
  int i,l;
  const char* d;
  l=bstrlen(c);
  d=bstrfirst(c);
  for (i=0; i<l; ++i)
    if (!isprint(d[i])) { printable=0; break; }
  if (printable) {
    buffer_puts(buffer_1," ");
    if (*c)
      buffer_puts(buffer_1,c);
    else
      buffer_put(buffer_1,bstrfirst(c),bstrlen(c));
  } else {
    char* e;
    i=fmt_base64(0,d,l);
    e=alloca(i+1);
    buffer_puts(buffer_1,": ");
    buffer_put(buffer_1,e,fmt_base64(e,d,l));
  }
}

int main(int argc,char* argv[]) {
  int verbose=1;
  unsigned long filelen;
  char* fn=argc<2?"data":argv[1];
  char* map=mmap_read(fn,&filelen);
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
  if (!map) {
    buffer_puts(buffer_2,"could not open ");
    buffer_puts(buffer_2,fn);
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    return 1;
  }
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
      buffer_puts(buffer_1,"dn:");
      uint32_unpack(x,&k);
      dumpbstr(map+k);
      buffer_puts(buffer_1,"\nobjectClass:");
      x+=4;
      uint32_unpack(x,&k);
      dumpbstr(map+k);
//      buffer_puts(buffer_1,map+k);
      buffer_puts(buffer_1,"\n");
      x+=4;
      for (; j>2; --j) {
	uint32_unpack(x,&k);
	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,":");
	uint32_unpack(x+4,&k);
	dumpbstr(map+k);
//	buffer_puts(buffer_1,map+k);
	buffer_puts(buffer_1,"\n");
	x+=8;
      }
      buffer_puts(buffer_1,"\n");
    }
  }
  buffer_flush(buffer_1);

  return 0;
}
