all: check-secret

clean:
	@rm -rf *.o
	@rm -rf check-secret

check-secret: check-secret.o aes.o
	gcc $(LDFLAGS) -o check-secret $^


# some test runs
test: check-secret
	echo -n '4f9886291b512f70611cde3188cdbc1b51d17da5ac4f8ea7af3ab8f10543f09e' | xxd -r -p | ./check-secret
	echo -n '0000000000000000000000000000000000000000000000000000000000000000' | xxd -r -p | ./check-secret || true