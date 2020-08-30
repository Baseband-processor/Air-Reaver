C_REAVER_DIR=C
PERL_AIR_REAVER_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_REAVER_DIR); make clean) && \
	(cd $(PERL_AIR_REAVER_DIR); make clean)
all: CT perlT
CT:
	(cd ./C && chmod 755 ./configure && ./configure --prefix=$(TMP_INSTALL_DIR)  && make && make install)
perlT:
	(cd ./$(PERL_AIR_REAVER_DIR) && sudo perl Makefile.PL  && make && make test && make install )
