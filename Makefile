###########################################################################
#
#	Makefile							
#
###########################################################################

MAKE	= make -j 4

SUBDIR	= hnc-16bit-4 hnc-16bit-6 hnc-32bit-4 openssl no-crypt

###########################################################################

all:	subdirs

subdirs:
	for i in $(SUBDIR) ; do \
		( cd $$i ; $(MAKE) ) ; \
	done

config:
	for i in $(SUBDIR) ; do \
		( cd $$i ; $(MAKE) $@ ) ; \
	done

install:
	for i in $(SUBDIR) ; do \
		( cd $$i ; $(MAKE) $@ ) ; \
	done

clean:
	for i in $(SUBDIR) ; do \
		( cd $$i ; $(MAKE) $@ ) ; \
	done

depend:
	for i in $(SUBDIR) ; do \
		( cd $$i ; $(MAKE) $@ ) ; \
	done
