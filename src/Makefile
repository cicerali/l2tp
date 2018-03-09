CC=gcc
CFLAGS=-I. -Wall -std=c99 -DLOG_USE_COLOR
LDFLAGS=-lpthread

SOURCES = log.c \
	  parser.c \
	  test.c \
	  fsm.c \
	  control.c \
	  data.c \
	  globals.c \
	  ppp.c \
	  l2tp.c

OBJECTS=$(SOURCES:.c=.o)	

BINARY=l2tp

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS) 

clean:
	rm -rf $(OBJECTS) $(BINARY)