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
freefilter.o freeava.o scan_ldapava.o fmt_ldapsearchresultentry.o \
fmt_ldapstring.o

ldif.a: ldif_parse.o

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

tinyldap: ldif.a

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
fmt_ldapbindrequest.o: fmt_ldapbindrequest.c asn1.h ldap.h
fmt_ldapbindresponse.o: fmt_ldapbindresponse.c asn1.h ldap.h
fmt_ldapmessage.o: fmt_ldapmessage.c asn1.h ldap.h

scan_asn1BOOLEAN.o: scan_asn1BOOLEAN.c asn1.h
scan_asn1ENUMERATED.o: scan_asn1ENUMERATED.c asn1.h
scan_asn1INTEGER.o: scan_asn1INTEGER.c asn1.h
scan_asn1SEQUENCE.o: scan_asn1SEQUENCE.c asn1.h
scan_asn1STRING.o: scan_asn1STRING.c asn1.h
scan_asn1int.o: scan_asn1int.c asn1.h
scan_asn1length.o: scan_asn1length.c asn1.h
scan_asn1string.o: scan_asn1string.c asn1.h
scan_asn1tag.o: scan_asn1tag.c asn1.h
scan_ldapava.o: scan_ldapava.c asn1.h ldap.h
scan_ldapbindrequest.o: scan_ldapbindrequest.c asn1.h ldap.h
scan_ldapbindresponse.o: scan_ldapbindresponse.c asn1.h ldap.h
scan_ldapmessage.o: scan_ldapmessage.c asn1.h ldap.h
scan_ldapsearchfilter.o: scan_ldapsearchfilter.c asn1.h ldap.h
scan_ldapsearchrequest.o: scan_ldapsearchrequest.c asn1.h ldap.h
scan_ldapstring.o: scan_ldapstring.c

ldif_parse.o: ldif_parse.c strduptab.h strstorage.h ldif.h

tinyldap.o: tinyldap.c ldap.h ldif.h
ldapclient.o: ldapclient.c ldap.h
bindrequest.o: bindrequest.c ldap.h

strduptab.o: strduptab.c strduptab.h strstorage.h
strstorage.o: strstorage.c strstorage.h
freeava.o: freeava.c ldap.h
freefilter.o: freefilter.c ldap.h
