CFLAGS = -g -fPIE
LDFLAGS = -pie

all: server

clean:
	@rm -rf *.o
	@rm -rf server

server: main.o httpd.o base64.o
	gcc $(LDFLAGS) -o server $^ -lcrypto

main.o: main.c httpd.h base64.h
httpd.o: httpd.c httpd.h
base64.o: base64.c base64.h

