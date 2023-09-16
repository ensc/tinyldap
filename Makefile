#DEBUG=1
#COVERAGE=1

all: libowfat-warning t1 t2 parse dumpidx idx2ldif addindex bindrequest tinyldap \
tinyldap_standalone tinyldap_debug ldapclient ldapclient_str \
md5password mysql2ldif acl dumpacls ldapdelete asn1dump tls.a x # t6 # t

pic pie:
	$(MAKE) all PIC=-fPIC LDFLAGS=-fpie

asn1.a: fmt_asn1intpayload.o fmt_asn1length.o fmt_asn1tag.o \
fmt_asn1int.o fmt_asn1string.o fmt_asn1transparent.o scan_asn1tag.o \
scan_asn1length.o scan_asn1int.o scan_asn1string.o scan_asn1INTEGER.o \
scan_asn1STRING.o scan_asn1SEQUENCE.o scan_asn1ENUMERATED.o \
scan_asn1BOOLEAN.o scan_asn1rawint.o scan_asn1SET.o fmt_asn1sint.o \
fmt_asn1sintpayload.o scan_asn1oid.o scan_asn1BITSTRING.o \
scan_asn1tagint.o fmt_asn1tagint.o fmt_asn1OID.o scan_asn1generic.o \
fmt_asn1generic.o scan_asn1rawoid.o fmt_asn1bitstring.o asn1oid.o \
scan_asn1SEQUENCE_nolengthcheck.o

ldap.a: scan_ldapmessage.o fmt_ldapmessage.o fmt_ldapbindrequest.o \
scan_ldapbindrequest.o scan_ldapbindresponse.o scan_ldapresult.o \
scan_ldapstring.o scan_ldapsearchfilter.o scan_ldapsearchrequest.o \
freefilter.o freeava.o scan_ldapava.o fmt_ldapsearchresultentry.o \
fmt_ldapstring.o freepal.o scan_ldapsearchresultentry.o \
fmt_ldapresult.o fmt_ldappal.o fmt_ldapadl.o fmt_ldapava.o \
fmt_ldapsearchfilter.o fmt_ldapsearchrequest.o matchstring.o \
matchprefix.o matchcasestring.o matchcaseprefix.o \
scan_ldapmodifyrequest.o scan_ldapaddrequest.o bstrlen.o bstrfirst.o \
bstrstart.o free_ldapadl.o free_ldappal.o free_ldapsearchfilter.o \
scan_ldapsearchfilterstring.o free_ldapsearchresultentry.o \
fmt_ldapsearchfilterstring.o ldap_match_sre.o \
fmt_ldapdeleterequest.o scan_ldapdeleterequest.o normalize_dn.o \
fmt_ldapmodifyrequest.o fmt_ldapaddrequest.o \
scan_ldapmessage_nolengthcheck.o

ldif.a: ldif_parse.o ldap_match_mapped.o

storage.a: strstorage.o strduptab.o mstorage_add.o mduptab_add.o \
bstr_diff.o mduptab_adds.o bstr_diff2.o mstorage_add_bin.o \
mstorage_init.o mstorage_init_persistent.o mstorage_unmap.o \
mduptab_init.o mduptab_init_reuse.o mduptab_reset.o

auth.a: auth.o

tls.a: fmt_tls_clienthello.o init_tls_context.o \
fmt_tls_serverhello.o fmt_tls_alert.o fmt_tls_packet.o \
tls_cipherprio.o fmt_tls_alert_pkt.o fmt_tls_handshake_cert.o \
fmt_tls_handshake_certs_header.o fmt_tls_serverhellodone.o \
tls_accept.o tls_connect.o tls_doread.o tls_dowrite.o

DIET=/opt/diet/bin/diet -Os
CROSS=
#CROSS=i686-mingw32-
CC=$(CROSS)gcc
CFLAGS=-pipe -I. -Wall -W -Wextra
ifneq ($(DEBUG),)
DIET=/opt/diet/bin/diet
CFLAGS=-pipe -I. -Wall -W -Wextra -g -fstack-protector
endif
ifeq ($(COVERAGE),1)
DIET=
CFLAGS=-pipe -I. -g -fprofile-arcs -ftest-coverage
endif

CFLAGS+=$(PIC)

ifneq ($(DIET),)
LIBS+=-llatin1
else
LIBS+=-lcrypto -lcrypt
endif

ifeq ($(CROSS),i686-mingw32-)
EXE=.exe
endif

%.o: %.c
	$(DIET) $(CC) $(CFLAGS) -c $<

%.a:
	$(CROSS)ar cru $@ $^

%: %.c
	$(DIET) $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lowfat ${LIBS}

.PHONY: libowfat-warning
libowfat-warning:
	@echo "#include <textcode.h>" > a.c
	@($(DIET) $(CC) $(CFLAGS) -c a.c >/dev/null 2>&1 && echo "WARNING: libowfat has moved the header files from foo.h to libowfat/foo.h\nWARNING: you still have foo.h! Please update your libowfat!") || exit 0
	@echo "#include <libowfat/textcode.h>" > a.c
	@$(DIET) $(CC) $(CFLAGS) -c a.c >/dev/null 2>&1 || echo "WARNING: this package needs libowfat; get it from https://www.fefe.de/libowfat/"
	@rm -f a.c a.o

t1 parse: ldif.a storage.a
t2: ldap.a asn1.a
t3 t4 t5 addindex: storage.a
t6: storage.a
tinyldap tinyldap_standalone tinyldap_debug: ldif.a storage.a auth.a
bindrequest tinyldap tinyldap_standalone tinyldap_debug ldapclient ldapclient_str ldapdelete: ldap.a asn1.a
idx2ldif: ldap.a
dumpacls: ldap.a asn1.a
parse: normalize_dn.o
asn1dump: asn1dump.c printasn1.c asn1.a
	$(DIET) $(CC) $(CFLAGS) -o $@$(EXE) $< $(LDFLAGS) -lowfat asn1.a

asn1dump.o: printasn1.c

tinyldap_standalone: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ $(LDFLAGS) -lowfat $(LIBS)

tinyldap_debug: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -DDEBUG -o $@ $^ $(LDFLAGS) -lowfat $(LIBS)

acl: acl.c ldap.a asn1.a
	$(DIET) $(CC) $(CFLAGS) -o acl acl.c -I. ldap.a asn1.a -lowfat $(LIBS)

.PHONY: test
test: test/bind test/ebind
	make -C test

test/%: test/%.c asn1.a ldap.a
	$(DIET) $(CC) $(CFLAGS) -o $@ $^ ldap.a asn1.a -lowfat $(LIBS)

.PHONY: clean tar
tar: clean
	cd ..; tar cvvf tinyldap.tar.bz2 tinyldap --use=bzip2 --exclude capture --exclude CVS --exclude exp.ldif --exclude polyp* --exclude rfc*

ldif_parse.o: ldif_parse.c strduptab.h strstorage.h ldif.h

tinyldap.o: tinyldap.c ldap.h ldif.h
ldapclient.o: ldapclient.c ldap.h
ldapclient_str.o: ldapclient_str.c ldap.h
bindrequest.o: bindrequest.c ldap.h

strduptab.o: strduptab.c strduptab.h strstorage.h
strstorage.o: strstorage.c strstorage.h
freeava.o: freeava.c ldap.h
freefilter.o: freefilter.c ldap.h

fmt_asn1int.o: fmt_asn1int.c asn1.h
fmt_asn1intpayload.o: fmt_asn1intpayload.c asn1.h
fmt_asn1length.o: fmt_asn1length.c asn1.h
fmt_asn1sint.o: fmt_asn1sint.c asn1.h
fmt_asn1sintpayload.o: fmt_asn1sintpayload.c asn1.h
fmt_asn1string.o: fmt_asn1string.c asn1.h
fmt_asn1tag.o: fmt_asn1tag.c asn1.h
fmt_asn1tagint.o: fmt_asn1tagint.c asn1.h
fmt_asn1transparent.o: fmt_asn1transparent.c asn1.h
fmt_ldapadl.o: fmt_ldapadl.c asn1.h ldap.h
fmt_ldapava.o: fmt_ldapava.c asn1.h ldap.h
fmt_ldapbindrequest.o: fmt_ldapbindrequest.c asn1.h ldap.h
fmt_ldapmessage.o: fmt_ldapmessage.c asn1.h ldap.h
fmt_ldappal.o: fmt_ldappal.c asn1.h ldap.h
fmt_ldapresult.o: fmt_ldapresult.c asn1.h ldap.h
fmt_ldapsearchfilter.o: fmt_ldapsearchfilter.c asn1.h ldap.h
fmt_ldapsearchfilterstring.o: fmt_ldapsearchfilterstring.c ldap.h
fmt_ldapsearchrequest.o: fmt_ldapsearchrequest.c asn1.h ldap.h
fmt_ldapsearchresultentry.o: fmt_ldapsearchresultentry.c asn1.h ldap.h
fmt_ldapstring.o: fmt_ldapstring.c asn1.h ldap.h
fmt_asn1OID.o: fmt_asn1OID.c asn1.h
fmt_asn1generic.o: fmt_asn1generic.c asn1.h
fmt_asn1bitstring.o: fmt_asn1bitstring.c asn1.h

scan_asn1BOOLEAN.o: scan_asn1BOOLEAN.c asn1.h
scan_asn1ENUMERATED.o: scan_asn1ENUMERATED.c asn1.h
scan_asn1INTEGER.o: scan_asn1INTEGER.c asn1.h
scan_asn1SEQUENCE.o: scan_asn1SEQUENCE.c asn1.h
scan_asn1SET.o: scan_asn1SET.c asn1.h
scan_asn1STRING.o: scan_asn1STRING.c asn1.h
scan_asn1BITSTRING.o: scan_asn1BITSTRING.c asn1.h
scan_asn1int.o: scan_asn1int.c asn1.h
scan_asn1length.o: scan_asn1length.c asn1.h
scan_asn1oid.o: scan_asn1oid.c asn1.h
scan_asn1rawoid.o: scan_asn1rawoid.c asn1.h
scan_asn1rawint.o: scan_asn1rawint.c asn1.h
scan_asn1string.o: scan_asn1string.c asn1.h
scan_asn1tag.o: scan_asn1tag.c asn1.h
scan_asn1tagint.o: scan_asn1tagint.c asn1.h
scan_ldapaddrequest.o: scan_ldapaddrequest.c asn1.h ldap.h
scan_ldapava.o: scan_ldapava.c asn1.h ldap.h
scan_ldapbindrequest.o: scan_ldapbindrequest.c asn1.h ldap.h
scan_ldapbindresponse.o: scan_ldapbindresponse.c asn1.h ldap.h
scan_ldapmessage.o: scan_ldapmessage.c asn1.h ldap.h
scan_ldapmodifyrequest.o: scan_ldapmodifyrequest.c asn1.h ldap.h
scan_ldapresult.o: scan_ldapresult.c asn1.h ldap.h
scan_ldapsearchfilter.o: scan_ldapsearchfilter.c asn1.h ldap.h
scan_ldapsearchfilterstring.o: scan_ldapsearchfilterstring.c ldap.h
scan_ldapsearchrequest.o: scan_ldapsearchrequest.c asn1.h ldap.h
scan_ldapsearchresultentry.o: scan_ldapsearchresultentry.c asn1.h ldap.h
scan_ldapstring.o: scan_ldapstring.c asn1.h ldap.h
scan_asn1generic.o: scan_asn1generic.c asn1.h

asn1oid.o: asn1oid.c asn1.h

init_tls_context.o: init_tls_context.c tinytls.h
fmt_tls_clienthello.o: fmt_tls_clienthello.c tinytls.h

ldap_match_sre.o: ldap_match_sre.c ldap.h

x: tls.a

privatekey.pem:
	openssl genrsa -out $@

windoze:
	$(MAKE) DIET= CROSS=i686-mingw32- asn1dump

static-analyzer:
	/opt/llvm/bin/scan-build --use-cc=/opt/llvm/bin/clang make DIET= -j4

fmt_tls_alert.o: fmt_tls_alert.c tinytls.h asn1.h
fmt_tls_alert_pkt.o: fmt_tls_alert_pkt.c tinytls.h asn1.h
fmt_tls_clienthello.o: fmt_tls_clienthello.c tinytls.h asn1.h
fmt_tls_handshake_cert.o: fmt_tls_handshake_cert.c tinytls.h asn1.h
fmt_tls_handshake_certs_header.o: fmt_tls_handshake_certs_header.c \
 tinytls.h asn1.h
fmt_tls_packet.o: fmt_tls_packet.c tinytls.h asn1.h
fmt_tls_serverhello.o: fmt_tls_serverhello.c tinytls.h asn1.h
fmt_tls_serverhellodone.o: fmt_tls_serverhellodone.c tinytls.h asn1.h
init_tls_context.o: init_tls_context.c tinytls.h asn1.h
tls_accept.o: tls_accept.c tinytls.h asn1.h
tls_cipherprio.o: tls_cipherprio.c
tls_connect.o: tls_connect.c tinytls.h asn1.h
tls_doread.o: tls_doread.c tinytls.h asn1.h
tls_dowrite.o: tls_dowrite.c tinytls.h asn1.h

WITH_UNITTEST = $(shell grep -l UNITTEST *.c)
UNITTEST_BIN = $(patsubst %.c, test/%, $(WITH_UNITTEST))

test/%: %.c
	$(CC) $(CFLAGS) --coverage -DUNITTEST -o $@ $^ -I. $(LDFLAGS)
	$@

check: $(UNITTEST_BIN)
	echo done

clean:
	rm -f t t[1-9] *.[ao] bindrequest tinyldap ldapclient \
parse tinyldap_standalone tinyldap_debug ldapclient_str addindex \
dumpidx idx2ldif md5password ldapdelete dumpacls asn1dump acl \
mysql2ldif x \
*.da *.bbg *.bb *.gcov gmon.out *.gcda *.gcno test/bind bind/ebind \
$(UNITTEST_BIN) test/*.gcda test/*.gcno test/*.gcov


