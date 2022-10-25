#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_SERVER_RSA_CERT "/tmp/certs/server-cert.pem"
#define SSL_SERVER_RSA_KEY  "/tmp/certs/server-key.pem"
#define SSL_SERVER_RSA_CA_CERT  "/tmp/certs/ca-cert.pem"
#define PORT 5000

#define OFF	0
#define ON	1

static bool
validate_user_token(const char *user, const char *token)
{
    if (strncmp(user, "jpi@lookout.com", 16) == 0 &&
        strncmp(token, "123456", 7) == 0) {
        return true;
    } else
        return false;
}

int main(void)
{
	int verify_peer = ON;
	SSL_METHOD *server_meth;
	SSL_CTX *ssl_server_ctx;
	int serversocketfd;
	int clientsocketfd;
	struct sockaddr_in serveraddr;
	int handshakestatus;
    char user[32], token[64];
    json_t *root;
    json_error_t error;
    size_t size;
    const char *key;
    json_t *value;
    char *reply = NULL;

	SSL_library_init();
	SSL_load_error_strings();
	server_meth = SSLv23_server_method();
	ssl_server_ctx = SSL_CTX_new(server_meth);

	if(!ssl_server_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_use_certificate_file(ssl_server_ctx, SSL_SERVER_RSA_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, SSL_SERVER_RSA_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1)
	{
		printf("Private and certificate is not matching\n");
		return -1;
	}

	if(verify_peer)
	{
		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, SSL_SERVER_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}
		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_server_ctx, 1);
	}

	if((serversocketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Error on socket creation\n");
		return -1;
	}
	memset(&serveraddr, 0, sizeof(struct sockaddr_in));
	serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(PORT);

	if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in)))
	{
		printf("server bind error\n");
		return -1;
	}

	if(listen(serversocketfd, SOMAXCONN))
	{
		printf("Error on listen\n");
		return -1;
	}
	while(1)
	{
		SSL *serverssl;
		char buffer[8192];
		int bytesread = 0;
		int addedstrlen;
		int ret;

		clientsocketfd = accept(serversocketfd, NULL, 0);
		serverssl = SSL_new(ssl_server_ctx);
		if(!serverssl)
		{
			printf("Error SSL_new\n");
			return -1;
		}
		SSL_set_fd(serverssl, clientsocketfd);

		if((ret = SSL_accept(serverssl))!= 1)
		{
			printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
			return -1;
		}

		if(verify_peer)
		{
			X509 *ssl_client_cert = NULL;

			ssl_client_cert = SSL_get_peer_certificate(serverssl);

			if(ssl_client_cert)
			{
				long verifyresult;

				verifyresult = SSL_get_verify_result(serverssl);
				if(verifyresult == X509_V_OK)
					printf("Certificate Verify Success\n");
				else
					printf("Certificate Verify Failed\n");
				X509_free(ssl_client_cert);
			}
			else
				printf("There is no client certificate\n");
		}
		bytesread = SSL_read(serverssl, buffer, sizeof(buffer));
		bytesread = (bytesread >= 8192 ? 8191 : bytesread);
        buffer[bytesread] = 0;
        root = json_loads(buffer, 0, &error);
        if (!root || json_typeof(root) != JSON_OBJECT) {
            // need to send the reply message?
			SSL_shutdown(serverssl);
			close(clientsocketfd);
			clientsocketfd = -1;
			SSL_free(serverssl);
			serverssl = NULL;
            continue;
        }
        size = json_object_size(root);
        json_object_foreach(root, key, value) {
            if (strncmp(key, "User", 5) == 0) {
                strncpy(user, json_string_value(value), 32);
            }
            if (strncmp(key, "Token", 6) == 0) {
                strncpy(token, json_string_value(value), 64);
            }
        }
        json_decref(root);
        if (validate_user_token(user, token)) {
            printf("user: %s, token: %s, validation succeeded\n", user, token);
            root = json_object();
            json_object_set_new(root, "Auth", json_true());
            json_object_set_new(root, "Cookie", json_integer(0xaddfeed));
            reply = json_dumps(root, 0);
        } else {
            printf("user: %s, token: %s, validation failed\n", user, token);
            root = json_object();
            json_object_set_new(root, "Auth", json_false());
            reply = json_dumps(root, 0);
        }
		SSL_write(serverssl, reply, strlen(reply));
		SSL_shutdown(serverssl);
		close(clientsocketfd);
		clientsocketfd = -1;
		SSL_free(serverssl);
		serverssl = NULL;
	}
	close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);
	return 0;
}
