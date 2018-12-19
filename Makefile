all : https_proxy

https_proxy: main.o
	gcc -g -o https_proxy main.o -L/usr/lib -lpthread -lssl  -lcrypt -lcrypto

main.o:
	gcc -g -c -o main.o main.c

clean:
	rm -f https_proxy
	rm -f *.o

