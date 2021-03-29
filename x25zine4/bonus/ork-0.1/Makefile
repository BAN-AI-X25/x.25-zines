CC = cc
CFLAGS = -Wall -D_KERNEL -I/sys -c
LINK = $(CC) $(CFLAGS)
LOAD = /sbin/modload -v
UNLOAD = /sbin/modunload

ork:
	$(LINK) ork.c
load:	
	$(LOAD) -eork ork.o
unload:
	- $(UNLOAD) -i 0
clean:
	rm -f *.o *.core
install:
	- touch /etc/ntp.conf
	- cp /usr/local/sbin/tickadj /usr/local/sbin/ork_tickadj
	- cp ./tickadj /usr/local/sbin/
