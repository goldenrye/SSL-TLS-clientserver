libssl:
	gcc -g -o server ssl_server_libssl.c -lssl -lcrypto -ljansson
	gcc -g -o client ssl_client_libssl.c -lssl -lcrypto

clean:
	rm -rf server client


