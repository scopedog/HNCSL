###########################################################################
#
#	Makefile							
#
###########################################################################

MAKE	= make -j 4

SUBDIR	= server client sec_eval

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
