obj-m+=cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) testcrypto.c -o crypto
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm crypto
