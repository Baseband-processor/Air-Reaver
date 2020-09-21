C_REAVER_DIR=C
PERL_AIR_REAVER_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_REAVER_DIR); make clean) && \
	(cd $(PERL_AIR_REAVER_DIR); make clean)
all: CT perlT
CT:
	(cd ./C/ && sudo chmod 755 ./configure && sudo ./configure --prefix=$(TMP_INSTALL_DIR)  && sudo make && sudo make install)
perlT:
	(cd ./$(PERL_AIR_REAVER_DIR) && sudo perl Makefile.PL  && sudo make && sudo make test && sudo make install )
