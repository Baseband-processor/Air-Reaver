VERSION = 20180302

MAJOR = 2
MINOR = 0
TINY = 0

HOME = @srcdir@
top_builddir = $(HOME)

prefix = @prefix@
exec_prefix = @exec_prefix@
datarootdir = @datarootdir@
ETC	= ${DESTDIR}@sysconfdir@
BIN	= ${DESTDIR}@bindir@
DATAROOT = ${DESTDIR}@datarootdir@
SHARE = ${DESTDIR}@datadir@/lorcon/
MAN = ${DESTDIR}@mandir@
LIB = ${DESTDIR}@libdir@
INCLUDE = ${DESTDIR}@includedir@

CC = @CC@
LDFLAGS = @LDFLAGS@ -L$(LIB)
LIBS = @LIBS@ @NLLIBS@
CFLAGS = -I./ @CPPFLAGS@ @CFLAGS@ @NLCFLAGS@ -DLORCON_VERSION=$(VERSION) -I$(INCLUDE)
SHELL = @SHELL@
LIBTOOL = @LIBTOOL@
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(CFLAGS)

DEPEND = .depend

LIBOBJ = ifcontrol_linux.lo iwcontrol.lo madwifing_control.lo nl80211_control.lo \
		wifi_ht_channels.lo \
		 lorcon_packet.lo lorcon_packasm.lo lorcon_forge.lo \
		 drv_mac80211.lo drv_tuntap.lo drv_madwifing.lo drv_hostap.lo drv_file.lo drv_wtgeneric.lo drv_wlanng.lo drv_airjack.lo drv_brcm43xx.lo drv_zd1211.lo drv_rt2570.lo drv_rt73.lo drv_rt61.lo drv_rt2500.lo drv_rtl.lo drv_madwifiold.lo drv_p54.lo \
		 sha1.lo  tx80211.lo \
		 lorcon.lo lorcon_multi.lo 
LIBOUT = liblorcon2.la

TXTESTOBJ = tx.o
TXTESTOUT = tx

TXTUNOBJ  = tools/tuntx.o
TXTUNOUT  = tools/tuntx

MCSSWEEP2OBJ = tools/mcs_sweep2.o
MCSSWEEP2OUT = tools/mcs_sweep2

all:	$(DEPEND) $(LIBOUT) 

$(LIBOUT):	$(LIBOBJ)
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $(LIBS) -o $(LIBOUT) $(LIBOBJ) \
					  -rpath $(LIB) -release $(MAJOR).$(MINOR).$(TINY)

$(TXTESTOUT):	$(TXTESTOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TXTESTOUT) $(TXTESTOBJ) $(LIBS) -lorcon2

$(TXTUNOUT):	$(TXTUNOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TXTUNOUT) $(TXTUNOBJ) $(LIBS) -lorcon2 -lpcap

$(MCSSWEEP2OUT):	$(MCSSWEEP2OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(MCSSWEEP2OUT) $(MCSSWEEP2OBJ) $(LIBS) -lorcon2 

tools:	$(LIBOUT) $(TXTUNOUT) $(L2PINGOUT) $(MCSSWEEP2OUT)

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


clean:
	@-rm -f *.o
	@-rm -f *.lo
	@-rm -f *.la
	@-rm -rf .libs
	@-rm -f $(TXTESTOUT)
	@-rm -f $(MCSSWEEP2OUT)
	@-rm -f $(TXTUNOUT)

distclean:
	@-$(MAKE) clean
	@-rm -f *~
	@-rm cscope.out
	@-rm -f $(DEPEND)
	@-rm -f config.status
	@-rm -f config.h
	@-rm -f config.log
	@-rm -f Makefile


dep:
	@$(MAKE) depend

depend:
	@$(MAKE) $(DEPEND)

$(DEPEND):
	@-rm -f $(DEPEND)
	@echo "Generating dependencies... "
	@echo > $(DEPEND)
	@$(CC) $(CFLAGS) -MM \
		`echo $(LIBOBJ) | sed -e "s/\.lo/\.c/g"` >> $(DEPEND)

include $(DEPEND)

.c.o:	$(DEPEND)
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.c.lo:	$(DEPEND)
	$(LTCOMPILE) -c $*.c -o $@

.SUFFIXES: .c .o .lo

