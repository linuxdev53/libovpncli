
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

#include "jsonc-helper.h"
#include "ctx.h"

#if 0

/*
 * connect to management socket
 */



/*
 * run openvpn process
 */

static int run_ovpn_proc(ovc_conn_mgr_t *conn_mgr)
{
	pid_t ovpn_pid;

	/* get free listen port */
	conn_mgr->mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (conn_mgr->mgm_port < 0)
		return -1;

	/* run openvpn process */
	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		char mgm_port_str[32];

		char *const ovpn_params[] = {
			conn_mgr->ctx->ops.ovpn_bin_path,
			"--config", conn_mgr->conn_params->profile_path,
			"--management", "127.0.0.1", mgm_port_str,
			NULL
		};

		snprintf(mgm_port_str, sizeof(mgm_port_str), "%d", conn_mgr->mgm_port);
		execv(conn_mgr->ctx->ops.ovpn_bin_path, ovpn_params);
		exit(1);
	} else if (ovpn_pid < 0)
		return -1;

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

	/* run openvpn process */
	ret = run_ovpn_proc(conn_mgr);
	if (ret != 0) {
		fprintf(stderr, "Could not run OpenVPN process\n");
		goto end;
	}

	/* connect to openvpn management socket */
	sleep(1);
	ret = connect_to_ovpn_mgm(conn_mgr);
	if (ret != 0) {
		fprintf(stderr, "Could not connect to OpenVPN management socket\n");
		goto end;
	}

	/* get VPN connection state */
	if (get_vpn_conn_state(conn_mgr) != 0) {
		fprintf(stderr, "The connection was established successfully\n");
		conn_mgr->conn_state = OVC_CONN_STATE_CONNECTED;
	} else {
		if (conn_mgr->end_flag || conn_mgr->conn_cancel)
			return 0;

		fprintf(stderr, "Failed to connect to VPN server\n");
		stop_vpn_conn(conn_mgr);
	}

	return 0;

end:
	stop_vpn_conn(conn_mgr);

	return 0;
}

#endif

/*
 * parse connection parameters
 */

static int parse_conn_params(ovc_conn_mgr_t *conn_mgr, const char *conn_json, ovc_conn_params_t *conn_params)
{
	char *proto = NULL;

	jhelper_object_t conn_params_opts[] = {
		{"profile_path", JSON_TYPE_STRING, true, &conn_params->profile_path},
		{"server_addr", JSON_TYPE_STRING, false, &conn_params->server_addr},
		{"proto", JSON_TYPE_STRING, false, &proto},
		{"port", JSON_TYPE_INT, false, &conn_params->port},
		{"auth_uname", JSON_TYPE_STRING, false, &conn_params->auth_uname},
		{"auth_passwd", JSON_TYPE_STRING, false, &conn_params->auth_passwd}
	};

	OVC_DEBUG_MSG(0, "Parsing connection parameters");

	/* init connection parameters */
	conn_params->port = -1;
	conn_params->proto = OVC_OVPN_PROTO_NONE;

	/* parse connection params */
	if (jhelper_parse_ex(conn_json, conn_params_opts) != 0) {
		OVC_DEBUG_ERR(0, "Failed to parse connection parameters");
		return -1;
	}

	/* set protocol */
	if (proto) {
		if (strcasecmp(proto, "tcp") == 0)
			conn_params->proto = OVC_OVPN_PROTO_TCP;
		else if (strcasecmp(proto, "udp") == 0)
			conn_params->proto = OVC_OVPN_PROTO_UDP;
		else {
			OVC_DEBUG_ERR(0, "Invalid OpenVPN protocol '%s'", proto);
			goto err;
		}
	}

	/* check port number */
	if (conn_params->port != -1 &&
		(conn_params->port <= 0 || conn_params->port >=65535)) {
		OVC_DEBUG_ERR(0, "Invalid port number '%d'", conn_params->port);
		goto err;
	}

	conn_mgr->conn_params_data = conn_params_opts;
	conn_mgr->conn_params_count = sizeof(conn_params_opts) / sizeof(jhelper_object_t);

	return 0;

err:
	jhelper_free_ex(conn_params_opts);

	return -1;
}

/*
 * start VPN connection
 */

int ovc_start_ovpn(ovc_conn_mgr_t *conn_mgr, const char *conn_json)
{
	ovc_conn_params_t conn_params;

	OVC_DEBUG_MSG(0, "Starting OpenVPN connection");

#if 0

	pthread_mutex_lock(&conn_mgr->conn_mt);


	/* set connection state */
	conn_mgr->conn_state = OVC_STATE_CONNECTING;

	/* parse connection parameters */
	memset(&conn_params, 0, sizeof(ovc_conn_params_t));
	if (parse_conn_params(conn_mgr, conn_json, &conn_params) != 0) {
		OVC_DEBUG_ERR(0, "Failed to parse JSON connection params");
		pthread_mutex_unlock(&conn_mgr->conn_mt);
		return -1;
	}

	/* create thread to start VPN connection */
	if (pthread_create(&conn_mgr->pt_conn, NULL, start_vpn_conn, (void *)conn_mgr) != 0) {
		fprintf(stderr, "Faield to start VPN connection thread\n");

		jhelper_free((jhelper_object_t *)conn_mgr->conn_params_data, conn_mgr->conn_params_count);
		conn_mgr->conn_state = OVC_CONN_STATE_DISCONNECTED;
		pthread_mutex_unlock(&conn_mgr->conn_mt);

		return -1;
	}

	pthread_mutex_unlock(&conn_mgr->conn_mt);
#endif

	return 0;
}

/*
 * stop openvpn connection
 */

static void stop_vpn_conn(ovc_conn_mgr_t *conn_mgr)
{

}

int ovc_stop_ovpn(ovc_conn_mgr_t *conn_mgr)
{
	return 0;
}


/*
 * monitor OpenVPN connection
 */

static void *monitor_ovpn_conn(void *p)
{
	ovc_conn_mgr_t *conn_mgr = (ovc_conn_mgr_t *)p;

	OVC_DEBUG_MSG(0, "Started OpenVPN connection monitoring thread");

	while (!conn_mgr->end_flag) {
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
	if (conn_mgr->conn_state != OVC_STATE_DISCONNECTED)
		stop_vpn_conn(conn_mgr);

	/* destroy mutex */
	pthread_mutex_destroy(&conn_mgr->conn_mt);
}
