obj-m := hello.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -D hello.ko $(DESTDIR)/lib/modules/$(shell uname -r)/kernel/drivers/net/hello.ko




