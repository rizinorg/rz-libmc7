NAME=mc7
ASM_NAME=asm_$(NAME)
ANAL_NAME=anal_$(NAME)

R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS=-g -fPIC -I../ $(shell pkg-config --cflags r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_anal)
ASM_OBJS=../simatic.o plugin-asm.o
ANAL_OBJS=../simatic.o plugin-anal.o
LIBEXT=$(shell r2 -H LIBEXT)
ASM_LIB=$(ASM_NAME).$(LIBEXT)
ANAL_LIB=$(ANAL_NAME).$(LIBEXT)

all: $(ASM_LIB) $(ANAL_LIB)

clean:
	rm -f $(ASM_LIB) $(ANAL_LIB) $(ASM_OBJS) $(ANAL_OBJS)

$(ASM_LIB): $(ASM_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ASM_OBJS) -o $(ASM_LIB)

$(ANAL_LIB): $(ANAL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ANAL_OBJS) -o $(ANAL_LIB)

install:
	cp -f $(ASM_LIB) $(R2_PLUGIN_PATH)
	cp -f $(ANAL_LIB) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(ASM_LIB)
	rm -f $(R2_PLUGIN_PATH)/$(ANAL_LIB)
