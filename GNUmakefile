PROGNAME=xdp-drop-ip-list
LIBS=-lbpf -lxdp
XDP_OPTS=-g -target bpf
CLANG_OPTS=-O2 -Wall
OBJECTS=xdp-drop-kern.o

.PHONY: default
default: $(PROGNAME)

$(PROGNAME): xdp-drop-launcher.c $(OBJECTS)
	clang $(CLANG_OPTS) xdp-drop-launcher.c -o $(PROGNAME) $(LIBS)
	chmod +x $(PROGNAME)

xdp-drop-kern.o: xdp-drop-kern.c
	clang $(CLANG_OPTS) $(XDP_OPTS) -c xdp-drop-kern.c -o xdp-drop-kern.o

.PHONY: clean
clean:
	rm $(OBJECTS) $(PROGNAME)
