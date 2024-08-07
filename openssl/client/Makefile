include ../../common/Makefile.common
EXECUTABLE	= openssl_client
MAIN		= main.c
INTERFACES	= net-common.c \
		  readconf.c misc-common.c log.c util.c \
		  pwcache.c mt19937-64.c
CC		= cc
SRCS		= $(MAIN) $(INTERFACES)
OBJS		= $(SRCS:.c=.o)
DEFS		= -DLOG_SSL_ERROR
LIBS		= -lutil -lpthread -lcrypto -lssl -levent
CFLAGS		= $(CCOPTS) $(DEFS) $(INCPATH)

##################################################################

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(EXECUTABLE) : $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBPATH) $(LIBS) -fprofile-generate

all : $(EXECUTABLE)

config:

install: all
	install -c -o root -g wheel $(EXECUTABLE) /usr/local/bin/

clean:
	rm -f AAA *.o *.core $(EXECUTABLE)

depend:
	mkdep $(CFLAGS) $(SRCS)

