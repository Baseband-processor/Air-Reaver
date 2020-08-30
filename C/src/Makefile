srcdir = .
INSTALL = ./install.sh
MKDIRP = mkdir -p

-include config.mak

LIBWPS_DIR=libwps
INC=-Ilibwps -I. -Ilwe

DISABLED_WARNINGS= \
 -Wno-unused-variable \
 -Wno-unused-function \
 -Wno-pointer-sign

CFLAGS=-DCONF_DIR='"$(CONFDIR)"' $(CFLAGS_USER) $(DISABLED_WARNINGS)
CFLAGS += $(INC)
CFLAGS += -DCONFIG_IPV6

UTILS_OBJS= \
        utils/base64.o \
        utils/common.o \
        utils/ip_addr.o \
        utils/radiotap.o \
        utils/trace.o \
        utils/uuid.o \
        utils/wpa_debug.o \
        utils/wpabuf.o \
	utils/os_unix.o \
	utils/vendor.o \
	utils/eloop.o


WPS_OBJS=wps/wps_attr_build.o wps/wps_attr_parse.o wps/wps_attr_process.o \
wps/wps.o wps/wps_common.o wps/wps_dev_attr.o wps/wps_enrollee.o \
wps/wps_registrar.o wps/wps_ufd.o

LWE_OBJS=lwe/iwlib.o

TLS_OBJS= \
 tls/asn1.o \
 tls/bignum.o \
 tls/pkcs1.o \
 tls/pkcs5.o \
 tls/pkcs8.o \
 tls/rsa.o \
 tls/tlsv1_client.o \
 tls/tlsv1_client_read.o \
 tls/tlsv1_client_write.o \
 tls/tlsv1_common.o \
 tls/tlsv1_cred.o \
 tls/tlsv1_record.o \
 tls/tlsv1_server.o \
 tls/tlsv1_server_read.o \
 tls/tlsv1_server_write.o \
 tls/x509v3.o

CRYPTO_OBJS= \
 crypto/aes-cbc.o \
 crypto/aes-ctr.o \
 crypto/aes-eax.o \
 crypto/aes-encblock.o \
 crypto/aes-internal.o \
 crypto/aes-internal-dec.o \
 crypto/aes-internal-enc.o \
 crypto/aes-omac1.o \
 crypto/aes-unwrap.o \
 crypto/aes-wrap.o \
 crypto/des-internal.o \
 crypto/dh_group5.o \
 crypto/dh_groups.o \
 crypto/md4-internal.o \
 crypto/md5.o \
 crypto/md5-internal.o \
 crypto/milenage.o \
 crypto/ms_funcs.o \
 crypto/rc4.o \
 crypto/sha1.o \
 crypto/sha1-internal.o \
 crypto/sha1-pbkdf2.o \
 crypto/sha1-tlsprf.o \
 crypto/sha1-tprf.o \
 crypto/sha256.o \
 crypto/sha256-internal.o \
 crypto/crypto_internal.o \
 crypto/crypto_internal-cipher.o \
 crypto/crypto_internal-modexp.o \
 crypto/crypto_internal-rsa.o \
 crypto/tls_internal.o \
 crypto/fips_prf_internal.o


LIB_OBJS=libwps/libwps.o $(WPS_OBJS) $(UTILS_OBJS) \
	$(TLS_OBJS) $(CRYPTO_OBJS) $(LWE_OBJS)


MAIN_OBJS=globule.o init.o sigint.o iface.o sigalrm.o \
 misc.o session.o send.o pins.o 80211.o builder.o \
 keys.o crc.o pixie.o version.o pcapfile.o

PROG_OBJS=$(MAIN_OBJS) exchange.o argsparser.o wpscrack.o wpsmon.o cracker.o main.o

# Version of the Wireless Tools
WT_VERSION := $(shell sed -ne "/WT_VERSION/{s:\([^0-9]*\)::;p;q;}" < lwe/iwlib.h )
# Version of Wireless Extensions.
WE_VERSION := $(shell sed -ne "/WE_VERSION/{s:\([^0-9]*\)::;p;q;}" < lwe/iwlib.h )
# Always use local header for wireless extensions
WEXT_HEADER = lwe/wireless.$(WE_VERSION).h

GENH = lwe/wireless.h version.h

all: wash reaver

$(WPS_OBJS): CFLAGS+=-I. -Iutils
$(TLS_OBJS): CFLAGS += -I. -Iutils -DCONFIG_INTERNAL_LIBTOMMATH -DCONFIG_CRYPTO_INTERNAL
$(CRYPTO_OBJS): CFLAGS += -I. -Iutils -DCONFIG_TLS_INTERNAL_CLIENT \
 -DCONFIG_TLS_INTERNAL_SERVER -fno-strict-aliasing


wash: reaver
	ln -sf ./reaver wash

reaver: $(PROG_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) $(INC) $(PROG_OBJS) $(LIB_OBJS) $(LDFLAGS) -lpthread -o reaver

extest.o: exchange.c
	$(CC) $(CFLAGS) -g3 -O0 -DEX_TEST -c exchange.c -o extest.o
extest: extest.o $(LIB_OBJS) $(MAIN_OBJS)
	$(CC) $(LIB_OBJS) extest.o $(MAIN_OBJS) $(LDFLAGS) -o extest

version.o: version.h
version.h: $(wildcard $(srcdir)/VERSION $(srcdir)/../.git)
	printf '#define R_VERSION "%s"\n' "$$(cd $(srcdir); sh version.sh)"  > $@

lwe/wireless.h: $(WEXT_HEADER)
	cp $(WEXT_HEADER) lwe/wireless.h

$(PROG_OBJS) $(LWE_OBJS): lwe/wireless.h

install: wash reaver
	install -D -m 755 wash $(DESTDIR)$(exec_prefix)/bin/wash
	install -D -m 755 reaver $(DESTDIR)$(exec_prefix)/bin/reaver
	install -d /usr/include/reaver/
	install -m 644  wpsmon.h /usr/include/reaver/wpsmon.h
	install -m 644  wpscrack.h /usr/include/reaver/wpscrack.h
	install -m 644  wps.h /usr/include/reaver/wps.h
	install -m 644  sigint.h /usr/include/reaver/sigint.h
	install -m 644  sigalrm.h /usr/include/reaver/sigalrm.h
	install -m 644  session.h /usr/include/reaver/session.h
	install -m 644  send.h /usr/include/reaver/send.h
	install -m 644  radiotap_flags.h /usr/include/reaver/radiotap_flags.h
	install -m 644  pixie.h /usr/include/reaver/pixie.h
	install -m 644  pins.h /usr/include/reaver/pins.h
	install -m 644  pcapfile.h /usr/include/reaver/pcapfile.h
	install -m 644  misc.h /usr/include/reaver/misc.h
	install -m 644  keys.h /usr/include/reaver/keys.h
	install -m 644  init.h /usr/include/reaver/init.h
	install -m 644  globule.h /usr/include/reaver/globule.h	
	install -m 644  exchange.h /usr/include/reaver/exchange.h
	install -m 644  iface.h /usr/include/reaver/iface.h
	install -m 644  defs.h /usr/include/reaver/defs.h
	install -m 644  crc.h /usr/include/reaver/crc.h
	install -m 644  cracker.h /usr/include/reaver/cracker.h
	install -m 644  cprintf.h /usr/include/reaver/cprintf.h
	install -m 644  builder.h /usr/include/reaver/builder.h
	install -m 644  argsparser.h /usr/include/reaver/argsparser.h
	install -m 644  80211.h /usr/include/reaver/80211.h
	install -d /usr/include/reaver/utils/
	install utils/* -t /usr/include/reaver/utils/
	install -d /usr/include/reaver/common/
	install common/* -t /usr/include/reaver/common/
	install -d /usr/include/reaver/crypto/
	install crypto/* -t  /usr/include/reaver/crypto/
	install -d /usr/include/reaver/libwps/
	install libwps/* -t /usr/include/reaver/libwps/
	install -d /usr/include/reaver/lwe/
	install lwe/* -t /usr/include/reaver/lwe/
	install -d /usr/include/reaver/wps/
	install wps/* -t /usr/include/reaver/wps


	@# create directory used to store *.wpc files;
	@# if not found defaults to "." i.e. current dir
	$(MKDIRP) $(DESTDIR)$(CONFDIR)

clean:
	rm -f reaver wash
	rm -f $(LIB_OBJS) $(PROG_OBJS)
	rm -f $(GENH)

.PHONY: all clean install

