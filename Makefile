DEBUG=1

all: t t1 t2 bindrequest tinyldap ldapclient

asn1.a: fmt_asn1intpayload.o fmt_asn1length.o fmt_asn1tag.o \
fmt_asn1int.o fmt_asn1string.o fmt_asn1transparent.o scan_asn1tag.o \
scan_asn1length.o scan_asn1int.o scan_asn1string.o scan_asn1INTEGER.o \
scan_asn1STRING.o scan_asn1SEQUENCE.o scan_asn1ENUMERATED.o \
scan_asn1BOOLEAN.o

ldap.a: scan_ldapmessage.o fmt_ldapmessage.o fmt_ldapbindrequest.o \
scan_ldapbindrequest.o fmt_ldapbindresponse.o scan_ldapbindresponse.o \
scan_ldapstring.o scan_ldapsearchfilter.o scan_ldapsearchrequest.o \
freefilter.o freeava.o scan_ldapava.o

DIET=diet -Os
CC=gcc
CFLAGS=-pipe -I. -Wall
ifneq ($(DEBUG),)
DIET=diet
CFLAGS=-pipe -I. -Wall -g
endif

%.o: %.c
	$(DIET) $(CC) $(CFLAGS) -c $<

%.a:
	ar cru $@ $^

%: %.c
	$(DIET) $(CC) $(CFLAGS) -o $@ $^ -lowfat

t1: strduptab.o strstorage.o
t2: ldap.a asn1.a
bindrequest tinyldap ldapclient: ldap.a asn1.a

strduptab.o: strduptab.c
	gcc $(CFLAGS) -c $^

.PHONY: clean tar
clean:
	rm -f t t1 t2 *.[ao] bindrequest tinyldap

tar: clean
	cd ..; tar cvvf ldap.tar.bz2 ldap --use=bzip2 --exclude CVS --exclude exp.ldif --exclude polyp* --exclude rfc*

fmt_asn1int.o: fmt_asn1int.c
fmt_asn1intpayload.o: fmt_asn1intpayload.c
fmt_asn1length.o: fmt_asn1length.c asn1.h
fmt_asn1string.o: fmt_asn1string.c asn1.h
fmt_asn1tag.o: fmt_asn1tag.c asn1.h
fmt_asn1transparent.o: fmt_asn1transparent.c asn1.h
scan_asn1int.o: scan_asn1int.c asn1.h
scan_asn1length.o: scan_asn1length.c asn1.h
scan_asn1string.o: scan_asn1string.c asn1.h
scan_asn1tag.o: scan_asn1tag.c asn1.h
scan_asn1INTEGER.o: scan_asn1INTEGER.c asn1.h
scan_asn1STRING.o: scan_asn1STRING.c asn1.h
scan_asn1SEQUENCE.o: scan_asn1SEQUENCE.c asn1.h
scan_ldapmessage.o: scan_ldapmessage.c asn1.h ldap.h
