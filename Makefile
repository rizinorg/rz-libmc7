OBJS     = simatic.o
BINS     = testsuite

CC       = gcc
CFLAGS   = -g -std=c99 -Os -Wall -W -Wno-ignored-qualifiers -I$(CURDIR) -DNDEBUG -D_FORTIFY_SOURCE=1 $(shell pkg-config --cflags r_util r_io r_cons r_core)
LDFLAGS  = $(shell pkg-config --libs r_util r_io r_cons r_core)

all:
	@$(MAKE) -C r2-simatic-s7
	@echo "built."

run_tests: $(BINS)
	@echo "built."
	./testsuite

$(BINS): %: %.o $(OBJS)
	@echo "[LD]" $@
	@$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS) 

clean:
	rm -f *.o $(BINS) *.exe *~
	@$(MAKE) -C r2-simatic-s7 clean

install:
	@$(MAKE) -C r2-simatic-s7 install

uninstall:
	@$(MAKE) -C r2-simatic-s7 uninstall
