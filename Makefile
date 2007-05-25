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
CFLAGS=$(FLAGS) -Wall -pedantic -O3 -D_POSIX_C_SOURCE=199506L -D_ISOC99_SOURCE -D_REENTRANT -DVERSION=\"0.25\"
LDFLAGS=-lpthread
NAME=cntlm

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

install: $(NAME)
	if [ -f /usr/bin/oslevel ]; then \
		install -O root -G system -M 0755 -S -f $(BINDIR) $(NAME); \
		install -O root -G system -M 0644 -f $(MANDIR)/man1 doc/$(NAME).1; \
		install -O root -G system -M 0600 -c $(SYSCONFDIR) doc/$(NAME).conf; \
	else \
		install -D -o root -g root -m 0755 -s $(NAME) $(BINDIR)/$(NAME); \
		install -D -o root -g root -m 0644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -o root -g root -m 0600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	fi

uninstall:
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	rm -f *.o tags cntlm pid massif* callgrind* 2>/dev/null

proxy.o: proxy.c
	if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) -c proxy.c -o $@; \
	else \
		$(CC) $(CFLAGS) -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c proxy.c -o $@; \
	fi
