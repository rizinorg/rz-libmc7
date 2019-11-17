OBJS     = simatic.o
BINS     = testsuite

CC       = gcc
CFLAGS   = -g -std=c99 -Os -Wall -W -Wno-ignored-qualifiers -I$(CURDIR) -DNDEBUG -D_FORTIFY_SOURCE=1 $(shell pkg-config --cflags r_util r_io r_cons r_core)
LDFLAGS  = $(shell pkg-config --libs r_util r_io r_cons r_core)

all: $(BINS)
	@echo "built."

$(BINS): %: %.o $(OBJS)
	@echo "[LD]" $@
	@$(CC) $(CXXFLAGS) -o $@ $< $(OBJS) $(LDFLAGS) 

clean:
	rm -f *.o $(BINS) *.exe *~

