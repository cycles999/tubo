#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/rsa.h"


//generate key
//generate x509
//set key and cert in ctx

struct socketInfo {
	int fd;
	struct sockaddr_in *addr;
};

struct data {
	int size;
	char buffer[65535];
};

EVP_PKEY* generateKeys() {
	EVP_PKEY_CTX *evppkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY *key_store = EVP_PKEY_new();

	EVP_PKEY_keygen_init(evppkey_ctx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(evppkey_ctx, 2048);

	EVP_PKEY_keygen(evppkey_ctx, &key_store);
	return key_store;
}


X509* generateEphemeralCert(EVP_PKEY* key_store) {
	X509 *cert = X509_new();

	//set cert valid timeframe between now and a year from now
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

	//set key to cert
	X509_set_pubkey(cert, key_store);

	//init name
	X509_NAME *name = X509_get_subject_name(cert);

	//assign name stuff
	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
		(unsigned char *)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
		(unsigned char *)"Tubo Server", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",  MBSTRING_ASC,
		(unsigned char *)"Tubo Server", -1, -1, 0);

	//assign name to cert
	X509_set_issuer_name(cert, name);

	//sign cert
	X509_sign(cert, key_store, EVP_sha1());

	return cert;
}

void createSocket(int port, struct socketInfo* info) {
	info->addr->sin_family = AF_INET;
	info->addr->sin_port = htons(port);
	info->addr->sin_addr.s_addr = htonl(INADDR_ANY);

	info->fd = socket(AF_INET, SOCK_STREAM, 0);
	if(info->fd < 0) {
		perror("Can't create socket");
		exit(EXIT_FAILURE);
	}

	if(bind(
		info->fd, 
		(struct sockaddr*)info->addr,
		sizeof(struct sockaddr_in)
	) < 0) {
		perror("Can't bind socket to port");
		exit(EXIT_FAILURE);
	}

	if(listen(info->fd, 1) < 0) {
		perror("Can't listen");
		exit(EXIT_FAILURE);
	}
}

int fifoPending(int fd) {
	int bytes_pending = 0;
	ioctl(fd, FIONREAD, &bytes_pending);
	return bytes_pending;
}


int main() {
	//generate key
	EVP_PKEY* key_store = generateKeys();

	//generate cert
	X509* cert = generateEphemeralCert(key_store);
	
	//generate ctx
	const SSL_METHOD *method = TLS_server_method();

	SSL_CTX *ctx = SSL_CTX_new(method);

	//configure context
	SSL_CTX_use_certificate(ctx, cert);
	SSL_CTX_use_PrivateKey(ctx, key_store);

	//create socket
	struct socketInfo info;
	struct sockaddr_in sock_addr;

	info.addr = &sock_addr;
	createSocket(3939, &info);

	//connect
	int addr_len = sizeof(sock_addr);
	int client_fd = accept(
		info.fd,
		(struct sockaddr*)info.addr,
		(socklen_t*)&addr_len
	);
	printf("alskdjad\n");

	//use ssl context to create ssl file descriptor
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_fd);

	//create named pipe
	mkfifo("./poopfart", 777);

	//open file descriptors to pipe
	int fifo_read = open("./poopfart", O_RDONLY | O_NONBLOCK);
	int fifo_write = open("./poopfart", O_WRONLY | O_NONBLOCK);

	//main loop
	//nonblocking read from connection, if something put in pipe
	//nonblocking read from pipe, if send over socket
	struct data dataFromPipe;
	struct data dataFromSocket;
	while(1) {
		if (SSL_pending(ssl) < 0) {
			SSL_read(ssl, &(dataFromSocket.size), sizeof(int));
			SSL_read(
				ssl, 
				&(dataFromSocket.buffer),
				dataFromSocket.size
			);
			write(
				fifo_write, 
				dataFromSocket.buffer, 
				dataFromSocket.size
			);
		}
		if ((dataFromPipe.size = fifoPending(fifo_read)) < 0) {
			read(
				fifo_read, 
				&(dataFromPipe.buffer),
				dataFromPipe.size
			);
			SSL_write(ssl, &dataFromPipe, sizeof(struct data));
		}
		
	}

	//free everything
	SSL_CTX_free(ctx);
	X509_free(cert);
	EVP_PKEY_free(key_store);

	//close all file descriptors
	//delete fifo
	return 0;
}



