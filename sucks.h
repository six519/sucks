#ifndef _SUCKS_H_
#define _SUCKS_H_

#include <libssh/libssh.h>
#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>

#define DEFAULT_CONF_FILE "config.cfg"
#define BUFFER_SIZE 524288
#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NO_AUTH 0x00
#define SOCKS5_AUTH_USERNAME_PASSWORD 0x02
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ADDR_IPV4 0x01
#define SOCKS5_ADDR_DOMAIN 0x03
#define SOCKS5_ADDR_IPV6 0x04

typedef struct {
	int client_socket;
	char *server_address;
	int ssh_port;
	const char *ssh_key_file;
	const char *ssh_host;
	const char *ssh_user;
} thread_args_t;

ssh_session ssh_session_init(int ssh_port, const char *ssh_key_file, const char *ssh_host, const char *ssh_user);
int proxy_server_init(struct sockaddr_in server_addresses, int max_connection);
int proxy_server_handshake(int client_socket, char *destination_address, size_t destination_address_length, uint16_t *destination_port);
void handle_network_traffic(ssh_session session, int client_socket, const char *destination_address, uint16_t destination_port, char *server_address);
void *handle_proxy_client(void *arg);
void load_configuration(config_t *cfg, int *proxy_port, int *max_connection, int *ssh_port, const char **ssh_key_file, const char **ssh_host, const char **ssh_user);

#endif