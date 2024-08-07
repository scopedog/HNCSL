ARCH	!= ./det-arch.sh
ARCH:sh	= uname -m
ARCH	?= $(shell uname -m)
ARCH	:= $(shell uname -m)
include Makefile.$(ARCH)
include Makefile.custom

OBJS	= $(SRCS:.c=.o)
CC	= cc
CCOPTS	=  -pipe -Wall -Ofast \
	   -Wno-unused-result -Wno-array-bounds \
           -Wno-format-truncation -Wno-stringop-truncation \
           -Wno-unknown-pragmas -Wno-unknown-warning-option
LIBS	=
DEFS	= -D_$(ARCH)_
CFLAGS	= $(CCOPTS) $(SIMDFLAGS) $(DEFS) $(INCPATH)

##################################################################

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET_LIB): $(OBJS)
	ar -crs $@ $(OBJS)

all: $(TARGET_LIB)

clean:
	rm -f *.o *.core *.a
