prefix ?= /usr/local
sbindir ?= $(prefix)/sbin
localstatedir ?= $(prefix)/var

RAND_src = rand.c
RAND_bin = rand
RAND_tgt = $(DESTDIR)$(sbindir)/$(RAND_bin)

$(RAND_bin) : LDFLAGS+=-lcrypto
$(RAND_bin) : $(RAND_src)

$(RAND_tgt) : $(RAND_bin)
	install -d $(DESTDIR)$(sbindir)
	intsall -d $(DESTDIR)$(localstatedir)/lib/$(RAND_bin)
	install -m 755 $^ $@

clean :
	-rm -f $(RAND_bin)

install : $(RAND_tgt)
