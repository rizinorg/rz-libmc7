TESTSUITE_OBJS     = simatic.o
TESTSUITE_BINS     = testsuite

TESTSUITE_CC       = gcc
TESTSUITE_CFLAGS   = -g -std=c99 -Os -Wall -W -Wno-ignored-qualifiers -I$(CURDIR) -DNDEBUG -D_FORTIFY_SOURCE=1 $(shell pkg-config --cflags r_util r_io r_cons r_core)
TESTSUITE_LDFLAGS  = $(shell pkg-config --libs r_util r_io r_cons r_core)

all:
	@$(MAKE) -C r2-simatic-s7
	@echo "built."

run_tests: $(TESTSUITE_BINS)
	@echo "built."
	./testsuite

$(TESTSUITE_BINS): %: %.o $(TESTSUITE_OBJS)
	@echo "[LD]" $@
	@$(TESTSUITE_CC) $(TESTSUITE_CFLAGS) -o $@ $< $(TESTSUITE_OBJS) $(TESTSUITE_LDFLAGS) 

clean:
	rm -f *.o $(BINS) *.exe *~
	@$(MAKE) -C r2-simatic-s7 clean

install:
	@$(MAKE) -C r2-simatic-s7 install

uninstall:
	@$(MAKE) -C r2-simatic-s7 uninstall
