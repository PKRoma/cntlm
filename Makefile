#
# You can tweak these three variables to make things install where you
# like, but do not touch more unless you know what you are doing. ;)
#
SYSCONFDIR=/usr/local/etc
BINDIR=/usr/local/bin
MANDIR=/usr/local/man

#
# Careful now...
#
CC=gcc
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o proxy.o
CFLAGS+=-Wall -pedantic -g -O3 -D_REENTRANT -DVERSION=\"0.23\"
LDFLAGS=-lpthread -g
NAME=cntlm

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

install: $(NAME)
	if [ -f /usr/bin/oslevel ]; then \
		install -O root -G root -M 0755 -S -f $(BINDIR)/ $(NAME); \
		install -O root -G root -M 0644 -f $(MANDIR)/man1/ doc/$(NAME).1; \
		install -O root -G root -M 0600 -c $(SYSCONFDIR)/ doc/$(NAME).conf; \
	else \
		install -D -o root -g root -m 0755 -s $(NAME) $(BINDIR)/$(NAME); \
		install -D -o root -g root -m 0644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -o root -g root -m 0600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	fi

uninstall: $(NAME)
	rm -f $(PREFIX)/bin/$(NAME) $(PREFIX)/share/man/man1/$(NAME).1 2>/dev/null || true

clean:
	rm -f *.o tags cntlm pid massif* callgrind* 2>/dev/null

proxy.o: proxy.c
	if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) -c $^ -o $@; \
	else \
		$(CC) $(CFLAGS) -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c $^ -o $@; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@
