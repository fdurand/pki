NAME	= inverse-pki
VERSION	= 1.00
PREFIX	= /usr/local/pf/pki
UID	= -o pf
GID	= -g pf
DIRS	= bootstrap3 inverse pki rest_framework conf
INSTALL	= /usr/bin/install -c -D -m0644
TAR	= $(NAME)-$(VERSION).tar
GZ	= $(TAR).gz
BZ2	= $(TAR).bz2

all:
		
install:
	for i in '$(DIRS)'; do \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $(UID) $(GID) $$j $(DESTDIR)$(PREFIX)/$$j; \
		fi; \
		done \
	done
	install -m0744 manage.py $(DESTDIR)$(PREFIX)/manage.py; \
	install -m0744 inverse-pki.wsgi $(DESTDIR)$(PREFIX)/inverse-pki.wsgi; \
	install -m0600 debian/httpd.conf.debian $(DESTDIR)$(PREFIX)/conf/httpd.conf
	
clean:
	rm -fr db*
