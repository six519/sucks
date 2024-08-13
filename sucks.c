#include "sucks.h"

ssh_session ssh_session_init(int ssh_port, const char *ssh_key_file, const char *ssh_host, const char *ssh_user) {
	ssh_key key = NULL;
	ssh_session session = ssh_new();
	if (session == NULL) return NULL;

	ssh_options_set(session, SSH_OPTIONS_HOST, ssh_host);
	ssh_options_set(session, SSH_OPTIONS_USER, ssh_user);
	ssh_options_set(session, SSH_OPTIONS_PORT, &ssh_port);

	int rc = ssh_connect(session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to ssh host: %s\n", ssh_get_error(session));
		ssh_free(session);
		return NULL;
	}

	rc = ssh_pki_import_privkey_file(ssh_key_file, NULL, NULL, NULL, &key);

	if (rc != SSH_OK) {
		fprintf(stderr, "Cannot import private key file: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return NULL;
	}

	rc = ssh_userauth_publickey(session, NULL, key);

	if (rc!=SSH_AUTH_SUCCESS) {
		fprintf(stderr, "SSH private key authentication failed: %s\n", ssh_get_error(session));
		ssh_key_free(key);
		ssh_disconnect(session);
		ssh_free(session);
		return NULL;
	}

	return session;
}

int proxy_server_init(struct sockaddr_in server_addresses, int max_connection) {
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "Socket creation failed\n");
		exit(EXIT_FAILURE);
	}

	if (bind(socket_fd, (struct sockaddr *)&server_addresses, sizeof(server_addresses)) < 0) {
		fprintf(stderr, "Socket bind failed\n");
		close(socket_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(socket_fd, max_connection) < 0) {
		fprintf(stderr, "Socket listen failed\n");
		close(socket_fd);
		exit(EXIT_FAILURE);
	}

	printf("Sucks proxy server listening on port %d\n", ntohs(server_addresses.sin_port));
	return socket_fd;
}

int proxy_server_handshake(int client_socket, char *destination_address, size_t destination_address_length, uint16_t *destination_port) {
	uint8_t buffer[262];
	ssize_t read_length;

	read_length = recv(client_socket, buffer, sizeof(buffer), 0);
	if (read_length < 2 || buffer[0] != SOCKS5_VERSION) {
		return EXIT_FAILURE;
	}

	uint8_t response[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NO_AUTH};
	if (send(client_socket, response, 2, 0) != 2) {
		return EXIT_FAILURE;
	}

	read_length = recv(client_socket, buffer, sizeof(buffer), 0);
	if (read_length < 7 || buffer[0] != SOCKS5_VERSION) {
		return EXIT_FAILURE;
	}

	if (buffer[1] != SOCKS5_CMD_CONNECT) {
		return EXIT_FAILURE;
	}

	if (buffer[3] == SOCKS5_ADDR_IPV4) {
		if (read_length < 10) return EXIT_FAILURE;
		inet_ntop(AF_INET, buffer + 4, destination_address, destination_address_length);
		memcpy(destination_port, buffer + 8, 2);
	} else if (buffer[3] == SOCKS5_ADDR_DOMAIN) {
		uint8_t domain_length = buffer[4];
		if (read_length < 5 + domain_length + 2) return EXIT_FAILURE;
		memcpy(destination_address, buffer + 5, domain_length);
		destination_address[domain_length] = '\0';
		memcpy(destination_port, buffer + 5 + domain_length, 2);
	} else if (buffer[3] == SOCKS5_ADDR_IPV6) {
		if (read_length < 22) return EXIT_FAILURE;
		inet_ntop(AF_INET6, buffer + 4, destination_address, destination_address_length);
		memcpy(destination_port, buffer + 20, 2);
	} else {
		return EXIT_FAILURE;
	}

	*destination_port = ntohs(*destination_port);
	uint8_t success_response[10] = {SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ADDR_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	if (send(client_socket, success_response, 10, 0) != 10) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void handle_network_traffic(ssh_session session, int client_socket, const char *destination_address, uint16_t destination_port, char *server_address) {
	ssh_channel channel = ssh_channel_new(session);
	char buffer[BUFFER_SIZE];
	ssize_t read_length, write_length;
	fd_set fds;
	int socket_fd = ssh_get_fd(session);

	if (channel == NULL) {
		close(client_socket);
		return;
	}

	if (ssh_channel_open_forward(channel, destination_address, destination_port, server_address, client_socket) != SSH_OK) {
		ssh_channel_free(channel);
		close(client_socket);
		return;
	}

	while(1) {
		FD_ZERO(&fds);
		FD_SET(client_socket, &fds);
		FD_SET(socket_fd, &fds);

		if (select(FD_SETSIZE, &fds, NULL, NULL, NULL) < 0) {
			break;
		}

		if (FD_ISSET(client_socket, &fds)) {
			read_length = recv(client_socket, buffer, sizeof(buffer), 0);
			if (read_length <= 0) break;
			write_length = ssh_channel_write(channel, buffer, read_length);
			if (write_length != read_length) break;
		}

		if (FD_ISSET(socket_fd, &fds)) {
			read_length = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
			if (read_length <= 0) break;
			write_length = send(client_socket, buffer, read_length, 0);
			if (write_length != read_length) break;
		}

	}

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	close(client_socket);
}

void *handle_proxy_client(void *arg) {
	thread_args_t *args = (thread_args_t *)arg;
	int client_socket = args->client_socket;
	char *server_address = args->server_address;
	int ssh_port = args->ssh_port;
	const char *ssh_key_file = args->ssh_key_file;
	const char *ssh_host = args->ssh_host;
	const char *ssh_user = args->ssh_user;
	free(args);
	char destination_address[256];
	uint16_t destination_port;

	if (proxy_server_handshake(client_socket, destination_address, sizeof(destination_address), &destination_port) == 0) {
		ssh_session session = ssh_session_init(ssh_port, ssh_key_file, ssh_host, ssh_user);
		if (session != NULL) {
			handle_network_traffic(session, client_socket, destination_address, destination_port, server_address);
			ssh_disconnect(session);
			ssh_free(session);
		}
	}

	close(client_socket);
	return NULL;
}

void load_configuration(config_t *cfg, int *proxy_port, int *max_connection, int *ssh_port, const char **ssh_key_file, const char **ssh_host, const char **ssh_user) {
	config_init(cfg);
	config_setting_t *setting;

	if(!config_read_file(cfg, DEFAULT_CONF_FILE)) {
		fprintf(stderr, "Unable to open configuration file: %s\n", DEFAULT_CONF_FILE);
		config_destroy(cfg);
		exit(EXIT_FAILURE);
	}

	setting = config_lookup(cfg, "configuration");
	if(setting == NULL) {
		fprintf(stderr, "Invalid configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_int(setting, "proxy_port", proxy_port)) {
		fprintf(stderr, "Missing proxy_port configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_int(setting, "proxy_max_connection", max_connection)) {
		fprintf(stderr, "Missing proxy_max_connection configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_int(setting, "ssh_port", ssh_port)) {
		fprintf(stderr, "Missing ssh_port configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_string(setting, "ssh_private_key", ssh_key_file)) {
		fprintf(stderr, "Missing ssh_private_key configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_string(setting, "ssh_host", ssh_host)) {
		fprintf(stderr, "Missing ssh_host configuration\n");
		exit(EXIT_FAILURE);
	}

	if(!config_setting_lookup_string(setting, "ssh_user", ssh_user)) {
		fprintf(stderr, "Missing ssh_user configuration\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv) {
	config_t cfg;
	int proxy_port;
	int max_connection;
	int ssh_port;
	const char *ssh_key_file;
	const char *ssh_host;
	const char *ssh_user;
	struct sockaddr_in serv_addr;
	pthread_t thread;

	load_configuration(&cfg, &proxy_port, &max_connection, &ssh_port, &ssh_key_file, &ssh_host, &ssh_user);

	ssh_session session = ssh_session_init(ssh_port, ssh_key_file, ssh_host, ssh_user);
	if (session == NULL) {
		fprintf(stderr, "Create ssh session failed\n");
		return(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(proxy_port);

	int proxy_sock = proxy_server_init(serv_addr, max_connection);

	while (1) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_socket = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_len);

		if (client_socket < 0) {
			fprintf(stderr, "Socket accept failed\n");
			continue;
		}

		thread_args_t *args = malloc(sizeof(thread_args_t));
		args->client_socket = client_socket;
		args->server_address = inet_ntoa(serv_addr.sin_addr);
		args->ssh_port = ssh_port;
		args->ssh_key_file = ssh_key_file;
		args->ssh_host = ssh_host;
		args->ssh_user = ssh_user;

		pthread_create(&thread, NULL, handle_proxy_client, (void *)args);
		pthread_detach(thread);
	}

	ssh_disconnect(session);
	ssh_free(session);
	close(proxy_sock);
	config_destroy(&cfg);
	return EXIT_SUCCESS;
}
