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

//connect to server
//create pipe
//open file handles

struct socketInfo {
	int fd;
	struct sockaddr_in *addr;
};

struct data {
	int size;
	char buffer[65535];
};

void createSocket(int port, struct socketInfo* info) {
	info->addr->sin_family = AF_INET;
	info->addr->sin_port = htons(port);
	info->addr->sin_addr.s_addr = inet_addr("127.0.0.1");

	info->fd = socket(AF_INET, SOCK_STREAM, 0);
}


int main() {
	printf("creating ssl context");
	//create ssl context
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	//create ssl struct
	SSL *ssl = SSL_new(ctx);

	//create tcp socket
	struct socketInfo info;
	struct sockaddr_in addr;
	int fd;

	info.addr = &addr;
	createSocket(3939, &info);
	fd = info.fd;

	int addr_len = sizeof(info.addr);
	int status = connect(fd, (struct sockaddr*)&(info.addr), addr_len);
	printf("%d %d\n", status, fd);
	
	//create ssl socket
	SSL_set_fd(ssl, fd);
}
