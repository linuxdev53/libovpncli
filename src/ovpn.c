
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "jsonc-helper.h"
#include "ctx.h"

static void *stop_vpn_conn(void *param);

/*
 * connect to OpenVPN management socket
 */

static int connect_to_ovpn_mgm(ovc_conn_mgr_t *conn_mgr)
{
	int sock;
	struct sockaddr_in mgm_addr;

	char mgm_cmd[512];
	char resp[512];

	int ret = -1;

	OVC_DEBUG_MSG(0, "Creating OpenVPN management socket");

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		OVC_DEBUG_ERR(0, "Failed to create socket(err:%d)", errno);
		return -1;
	}

	/* set management address */
	memset(&mgm_addr, 0, sizeof(mgm_addr));
	mgm_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(mgm_addr.sin_addr));
	mgm_addr.sin_port = htons(conn_mgr->mgm_port);

	/* connet to openvpn management console */
	if (connect(sock, (const struct sockaddr *) &mgm_addr, sizeof(struct sockaddr_in)) != 0) {
		OVC_DEBUG_ERR(0, "VPN: Couldn't connect to OpenVPN management console '127.0.0.1:%d'(err:%d)",
				conn_mgr->mgm_port, errno);
		goto end;
	}

	/* get first response from management socket */
	if (recv(sock, resp, sizeof(resp), 0) <= 0) {
		OVC_DEBUG_ERR(0, "Couldn't get first response from OpenVPN management socket(err:%d)", errno);
		goto end;
	}

	/* send command to openvpn management */
	strlcpy(mgm_cmd, "state on\n", sizeof(mgm_cmd));
	if (conn_mgr->ctx->ops.report_ovpn_log)
		strlcat(mgm_cmd, "log on\n", sizeof(mgm_cmd));

	if (conn_mgr->ctx->ops.report_byte_count)
		strlcat(mgm_cmd, "bytecount 10\n", sizeof(mgm_cmd));

	if (send(sock, mgm_cmd, strlen(mgm_cmd), 0) <= 0) {
		OVC_DEBUG_ERR(0, "Failed to send command '%s' to OpenVPN management socket(err:%d)",
				mgm_cmd, errno);
		goto end;
	}

	if (recv(sock, resp, sizeof(resp) - 1, 0) <= 0) {
		OVC_DEBUG_ERR(0, "Failed to get response from OpenVPN management socket(err:%d)",
				errno);
		goto end;
	}

	OVC_DEBUG_MSG(0, "Connection to OpenVPN management has suceeded");

	/* set management socket */
	conn_mgr->mgm_sock = sock;
	ret = 0;

end:
	if (ret != 0)
		close(sock);

	return ret;
}


/*
 * run openvpn process
 */

static int run_ovpn_proc(ovc_conn_mgr_t *conn_mgr)
{
	pid_t ovpn_pid;

	/* get free listen port */
	conn_mgr->mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (conn_mgr->mgm_port < 0) {
		OVC_DEBUG_ERR(0, "Failed to get free listen management port");
		return -1;
	}

	/* add args for running openvpn */
	add_cmdline_args(&conn_mgr->cmd_args, &conn_mgr->cmd_args_count,
			"%s --config %s --management 127.0.0.1 %d %s",
			conn_mgr->ctx->ops.ovpn_bin_path,
			conn_mgr->conn_params.profile_path,
			conn_mgr->mgm_port,
			conn_mgr->conn_params.extra_options);

	if (strlen(conn_mgr->conn_params.remote_addr) > 0) {
		add_cmdline_args(&conn_mgr->cmd_args, &conn_mgr->cmd_args_count,
				"--remote %s",
				conn_mgr->conn_params.remote_addr);
	}

	if (conn_mgr->conn_params.remote_port > 0) {
		add_cmdline_args(&conn_mgr->cmd_args, &conn_mgr->cmd_args_count,
				"--port %d",
				conn_mgr->conn_params.remote_port);
	}

	if (conn_mgr->conn_params.proto != OVC_OVPN_PROTO_NONE) {
		add_cmdline_args(&conn_mgr->cmd_args, &conn_mgr->cmd_args_count,
				"--proto %s",
				conn_mgr->conn_params.proto == OVC_OVPN_PROTO_UDP ? "udp" : "tcp");
	}

	if (!conn_mgr->cmd_args) {
		OVC_DEBUG_ERR(0, "Out of memory!");
		return -1;
	}

	/* run openvpn process */
	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		execv(conn_mgr->ctx->ops.ovpn_bin_path, conn_mgr->cmd_args);
		exit(1);
	} else if (ovpn_pid < 0)
		return -1;

	OVC_DEBUG_MSG(0, "OpenVPN process has been started successfully(pid:%d)", ovpn_pid);

	conn_mgr->ovpn_pid = ovpn_pid;

	return 0;
}

/*
 * start VPN connection thread
 */

static void *start_vpn_conn(void *p)
{
	ovc_conn_mgr_t *conn_mgr = (ovc_conn_mgr_t *)p;
	int ret;

	OVC_DEBUG_MSG(0, "Starting VPN connection thread");

	/* run openvpn process */
	ret = run_ovpn_proc(conn_mgr);
	if (ret != 0) {
		OVC_DEBUG_ERR(0, "Failed to run OpenVPN process");
		goto end;
	}

	/* connection to openvpn management socket */
	sleep(1);
	ret = connect_to_ovpn_mgm(conn_mgr);
	if (ret != 0) {
		OVC_DEBUG_ERR(0, "Failed to connect OpenVPN management socket");
		goto end;
	}

	return 0;

end:
	stop_vpn_conn(conn_mgr);

	return 0;
}

/*
 * parse connection parameters
 */

static int parse_conn_params(ovc_conn_mgr_t *conn_mgr, const char *conn_json)
{
	ovc_conn_params_t *conn_params = &conn_mgr->conn_params;
	char proto[OVC_MAX_PROTO];

	jhelper_object_t conn_params_opts[] = {
		{"profile_path", JSON_TYPE_STRING, true, conn_params->profile_path, sizeof(conn_params->profile_path)},
		{"server_addr", JSON_TYPE_STRING, false, conn_params->remote_addr, sizeof(conn_params->remote_addr)},
		{"proto", JSON_TYPE_STRING, false, proto, sizeof(proto)},
		{"port", JSON_TYPE_INT, false, &conn_params->remote_port, 0},
		{"extra_options", JSON_TYPE_STRING, false, conn_params->extra_options, sizeof(conn_params->extra_options)},
		{"auth_uname", JSON_TYPE_STRING, false, conn_params->auth_uname, sizeof(conn_params->auth_uname)},
		{"auth_passwd", JSON_TYPE_STRING, false, conn_params->auth_passwd, sizeof(conn_params->auth_passwd)}
	};

	OVC_DEBUG_MSG(0, "Parsing connection parameters");

	/* init connection parameters */
	memset(conn_params, 0, sizeof(ovc_conn_params_t));
	conn_params->remote_port = -1;
	conn_params->proto = OVC_OVPN_PROTO_NONE;
	proto[0] = '\0';

	/* parse connection params */
	if (jhelper_parse_ex(conn_json, conn_params_opts) != 0) {
		OVC_DEBUG_ERR(0, "Failed to parse connection parameters");
		return -1;
	}

	/* set protocol */
	if (strlen(proto) > 0) {
		if (strcasecmp(proto, "tcp") == 0)
			conn_params->proto = OVC_OVPN_PROTO_TCP;
		else if (strcasecmp(proto, "udp") == 0)
			conn_params->proto = OVC_OVPN_PROTO_UDP;
		else {
			OVC_DEBUG_ERR(0, "Invalid OpenVPN protocol '%s'", proto);
			return -1;
		}
	}

	/* check port number */
	if (conn_params->remote_port != -1 &&
		(conn_params->remote_port <= 0 || conn_params->remote_port >=65535)) {
		OVC_DEBUG_ERR(0, "Invalid port number '%d'", conn_params->remote_port);
		return -1;
	}

	return 0;
}

/*
 * start VPN connection
 */

int ovc_start_ovpn(ovc_conn_mgr_t *conn_mgr, const char *conn_json)
{
	int ret = 0;

	OVC_DEBUG_MSG(0, "Starting OpenVPN connection");

	pthread_mutex_lock(&conn_mgr->conn_mt);

	/* set connection state */
	conn_mgr->conn_state = OVC_STATE_CONNECTING;

	/* parse connection parameters */
	if (parse_conn_params(conn_mgr, conn_json) != 0) {
		OVC_DEBUG_ERR(0, "Failed to parse JSON connection params");
		pthread_mutex_unlock(&conn_mgr->conn_mt);
		return -1;
	}

	/* create thread to start VPN connection */
	if (pthread_create(&conn_mgr->pt_conn, NULL, start_vpn_conn, (void *)conn_mgr) != 0) {
		OVC_DEBUG_ERR(0, "Faield to start VPN connection thread\n");

		conn_mgr->conn_state = OVC_STATE_DISCONNECTED;
		ret = -1;
	}
	pthread_mutex_unlock(&conn_mgr->conn_mt);

	return ret;
}

/*
 * stop openvpn connection
 */

static void *stop_vpn_conn(void *param)
{
	ovc_conn_mgr_t *conn_mgr = (ovc_conn_mgr_t *)param;

	OVC_DEBUG_MSG(0, "Started thread to stop OpenVPN connection");

	/* close openvpn management socket */
	if (conn_mgr->mgm_sock > 0) {
		close(conn_mgr->mgm_sock);
		conn_mgr->mgm_sock = -1;
	}

	/* send sigterm to openvpn process */
	if (conn_mgr->ovpn_pid > 0) {
		OVC_DEBUG_MSG(0, "Try to send SIGTERM to OpenVPN process '%d'", conn_mgr->ovpn_pid);

		/* send SIGTERM signal to openvpn process */
		if (kill(conn_mgr->ovpn_pid, SIGTERM) != 0) {
			OVC_DEBUG_ERR(0, "Failed to send SIGTERM signal to OpenVPN process(err:%d)", errno);
		} else {
			int w, status;

			do {
				w = waitpid(conn_mgr->ovpn_pid, &status, WNOHANG);
				if (w < 0)
					break;
				else if (w == 0)
					sleep(1);

				if (WIFEXITED(status))
					break;
			} while(1);

			OVC_DEBUG_MSG(0, "OpenVPN process(pid:%d) has been terminated", conn_mgr->ovpn_pid);
		}

		/* init pid */
		conn_mgr->ovpn_pid = 0;
	}

	if (conn_mgr->cmd_args) {
		int i;

		for (i = 0; i < conn_mgr->cmd_args_count; i++)
			free(conn_mgr->cmd_args[i]);
		free(conn_mgr->cmd_args);

		conn_mgr->cmd_args = NULL;
		conn_mgr->cmd_args_count = 0;
	}

	return 0;
}

int ovc_stop_ovpn(ovc_conn_mgr_t *conn_mgr, bool is_non_block)
{
	int ret = 0;

	pthread_mutex_lock(&conn_mgr->conn_mt);

	OVC_DEBUG_MSG(0, "Stopping current OpenVPN connection");

	/* set connection cancel flag */
	conn_mgr->conn_cancel = true;

	/* check if connecting thread is in pending */
	if (conn_mgr->conn_state == OVC_STATE_CONNECTING) {
		OVC_DEBUG_MSG(0, "Wait until stopping current pending connection");
		pthread_join(conn_mgr->pt_conn, NULL);
	}

	/* create thread to stop VPN connection */
	if (pthread_create(&conn_mgr->pt_disconn, NULL, stop_vpn_conn, (void *)conn_mgr) != 0) {
		OVC_DEBUG_ERR(0, "Failed to create a thread to stop OpenVPN connection");
		ret = -1;
	} else if (!is_non_block)
		pthread_join(conn_mgr->pt_disconn, NULL);

	pthread_mutex_unlock(&conn_mgr->conn_mt);

	return 0;
}

/*
 * send openvpn notify
 */

static void send_ovpn_notify(ovc_conn_mgr_t *conn_mgr, enum OVC_NOTIFY_TYPES notify_type, const char *notify_data)
{
	char *notify_msg = NULL;

	jhelper_object_t ovpn_notify_jobjs[] = {
		{"type", JSON_TYPE_INT, false, &notify_type, 0},
		{"data", JSON_TYPE_STRING, false, (void *)notify_data, 0}
	};

	if (jhelper_build_ex(ovpn_notify_jobjs, &notify_msg) != 0)
		return;

	conn_mgr->ctx->notify_cb(notify_msg);
	free(notify_msg);
}

/*
 * parse byte counts
 */

static void parse_byte_counts(ovc_conn_mgr_t *conn_mgr, char *buf)
{
	char bytes[64];
	char *p = buf, *byte_count_jstr = NULL;

	jhelper_object_t byte_count_jobjs[] = {
		{"in", JSON_TYPE_INT64, false, &conn_mgr->bytes_in, 0},
		{"out", JSON_TYPE_INT64, false, &conn_mgr->bytes_out, 0}
	};

	/* get in bytes */
	get_token_by_char(&p, ',', bytes, sizeof(bytes));
	conn_mgr->bytes_in = strtol(bytes, NULL, 10);

	/* get out bytes */
	get_token_by_char(&p, ',', bytes, sizeof(bytes));
	conn_mgr->bytes_out = strtol(bytes, NULL, 10);

	/* build notification string for byte count */
	if (jhelper_build_ex(byte_count_jobjs, &byte_count_jstr) != 0)
		return;

	send_ovpn_notify(conn_mgr, OVC_NOTIFY_TYPE_BYTECOUNT, byte_count_jstr);
	free(byte_count_jstr);
}

/*
 * parse OpenVPN connection state
 */

struct voc_ovpn_state {
	enum OVPN_STATE ovpn_state;
	char *ovpn_state_str;
} g_ovpn_state[] = {
	{OVPN_STATE_TCP_CONNECT, "TCP_CONNECT"},
	{OVPN_STATE_WAIT, "WAIT"},
	{OVPN_STATE_AUTH, "AUTH"},
	{OVPN_STATE_GETCONFIG, "GET_CONFIG"},
	{OVPN_STATE_ASSIGNIP, "ASSIGN_IP"},
	{OVPN_STATE_ADDROUTES, "ADD_ROUTES"},
	{OVPN_STATE_CONNECTED, "CONNECTED"},
	{OVPN_STATE_RECONNECTING, "RECONNECTING"},
	{OVPN_STATE_EXITING, "EXITING"},
	{OVPN_STATE_UNKNOWN, NULL}
};

static void parse_ovpn_states(ovc_conn_mgr_t *conn_mgr, char *buf)
{
	char ts_str[32];
	char conn_state[64];

	int i;

	get_token_by_char(&buf, ',', ts_str, sizeof(ts_str));
	get_token_by_char(&buf, ',', conn_state, sizeof(conn_state));
	for (i = 0; g_ovpn_state[i].ovpn_state_str != NULL; i++) {
		if (strcmp(conn_state, g_ovpn_state[i].ovpn_state_str) == 0) {
			conn_mgr->ovpn_state = g_ovpn_state[i].ovpn_state;
			break;
		}
	}

	if (conn_mgr->ovpn_state == OVPN_STATE_CONNECTED) {
		char desc[128];

		get_token_by_char(&buf, ',', desc, sizeof(desc));
		get_token_by_char(&buf, ',', conn_mgr->tun_ip, sizeof(conn_mgr->tun_ip));

		conn_mgr->connected_tm = strtol(ts_str, NULL, 10);
	}

	/* send notification for connection state */
	send_ovpn_notify(conn_mgr, OVC_NOTIFY_TYPE_STATE, conn_state);
}

/*
 * parse response from OpenVPN management
 */

static void parse_mgm_resp(ovc_conn_mgr_t *conn_mgr, char *buffer)
{
	char *tok, *p, *rest;
	char sep[] = "\n";

	for (tok = strtok_r(buffer, sep, &rest); tok != NULL; tok = strtok_r(NULL, sep, &rest)) {
		if (strncmp(tok, OVPN_MGM_BYTECOUNT, strlen(OVPN_MGM_BYTECOUNT)) == 0)
			parse_byte_counts(conn_mgr, tok + strlen(OVPN_MGM_BYTECOUNT));
		else if (strncmp(tok, OVPN_MGM_STATE, strlen(OVPN_MGM_STATE)) == 0) {
			parse_ovpn_states(conn_mgr, tok + strlen(OVPN_MGM_STATE));
		}
	}
}

/*
 * monitor OpenVPN connection
 */

static void *monitor_ovpn_conn(void *param)
{
	ovc_conn_mgr_t *conn_mgr = (ovc_conn_mgr_t *)param;

	OVC_DEBUG_MSG(0, "Started OpenVPN connection monitoring thread");

	while (!conn_mgr->end_flag) {
		fd_set fds;
		struct timeval tv;

		int ret;

		char resp[512];

		/* check if management socket is created */
		if (conn_mgr->mgm_sock < 0) {
			sleep(1);
			continue;
		}

		/* set fds */
		FD_ZERO(&fds);
		FD_SET(conn_mgr->mgm_sock, &fds);

		tv.tv_sec = 0;
		tv.tv_usec = 50;

		/* get I/O event on management socket */
		ret = select(conn_mgr->mgm_sock + 1, &fds, NULL, NULL, &tv);
		if (ret < 0) {
			OVC_DEBUG_ERR(0, "The exception is generated in select() call(err:%d)", errno);
			break;
		}

		if (!FD_ISSET(conn_mgr->mgm_sock, &fds)) {
			usleep(50 * 1000);
			continue;
		}

		ret = recv(conn_mgr->mgm_sock, resp, sizeof(resp) - 1, 0);
		if (ret > 0) {
			resp[ret] = '\0';

			/* parse the response from openvpn management */
			parse_mgm_resp(conn_mgr, resp);
		}

		sleep(1);
	}

	OVC_DEBUG_MSG(0, "Stopped OpenVPN connection monitoring thread");

	return 0;
}

/*
 * init openvpn manager
 */

int ovc_init_ovpn(struct ovc_ctx_priv *ctx)
{
	ovc_conn_mgr_t *conn_mgr = &ctx->conn_mgr;

	OVC_DEBUG_MSG(0, "Initializing OpenVPN connection manager");

	/* init connection manager */
	conn_mgr->conn_state = OVC_STATE_DISCONNECTED;
	conn_mgr->mgm_sock = conn_mgr->mgm_port = -1;

	pthread_mutex_init(&conn_mgr->conn_mt, NULL);
	conn_mgr->init_status = true;

	conn_mgr->ctx = ctx;

	/* create thread to monitor VPN connection */
	if (pthread_create(&conn_mgr->pt_mon, NULL, monitor_ovpn_conn, (void *)conn_mgr) != 0) {
		fprintf(stderr, "Failed to start connection monitoring thread(err:%d)\n", errno);
		return -1;
	}

	return 0;
}

/*
 * finalize openvpn manager
 */

void ovc_finalize_ovpn(ovc_conn_mgr_t *conn_mgr)
{
	if (!conn_mgr->init_status)
		return;

	OVC_DEBUG_MSG(0, "Finalizing OpenVPN conneciton manager");

	/* set end flag */
	conn_mgr->end_flag = true;

	/* wait until connection monitoring thread has been finished */
	pthread_join(conn_mgr->pt_mon, NULL);

	/* if connection state isn't disconnected, then stop connection */
	ovc_stop_ovpn(conn_mgr, false);

	/* destroy mutex */
	pthread_mutex_destroy(&conn_mgr->conn_mt);
}
