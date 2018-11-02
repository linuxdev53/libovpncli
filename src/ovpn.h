#ifndef __LIBOVPN_OVPN_H__
#define __LIBOVPN_OVPN_H__

/*
 * OpenVPN management port starting point
 */

#define OVPN_MGM_PORT_START                6001

#define OVPN_MGM_BYTECOUNT                 ">BYTECOUNT:"
#define OVPN_MGM_STATE                     ">STATE:"
#define OVPN_MGM_REMOTE                    ">REMOTE:"

/*
 * OpenVPN state
 */

enum OVPN_STATE {
	OVPN_STAET_INIT = 0,
	OVPN_STATE_TCP_CONNECT,
	OVPN_STATE_WAIT,
	OVPN_STATE_AUTH,
	OVPN_STATE_GETCONFIG,
	OVPN_STATE_ASSIGNIP,
	OVPN_STATE_ADDROUTES,
	OVPN_STATE_CONNECTED,
	OVPN_STATE_RECONNECTING,
	OVPN_STATE_EXITING,
	OVPN_STATE_UNKNOWN
};

/*
 * OpenVPN connection states
 */

enum OVC_CONN_STATE {
	OVC_STATE_DISCONNECTED = 0,
	OVC_STATE_CONNECTING,
	OVC_STATE_DISCONNECTING,
	OVC_STATE_CONNECTED
};

/*
 * OpenVPN connection protocol
 */

enum OVC_OVPN_PROTO {
	OVC_OVPN_PROTO_UDP = 0,
	OVC_OVPN_PROTO_TCP,
	OVC_OVPN_PROTO_NONE
};

/*
 * OpenVPN connection parameters
 */

typedef struct ovc_conn_params {
	char profile_path[OVC_MAX_PATH];

	char remote_addr[OVC_MAX_HNAME];
	int remote_port;
	enum OVC_OVPN_PROTO proto;

	char extra_options[OVC_MAX_CMDLINE];

	char auth_uname[OVC_MAX_UNAME];
	char auth_passwd[OVC_MAX_PASSWD];
} ovc_conn_params_t;

/*
 * openvpn manager structure
 */

typedef struct ovc_conn_mgr {
	bool init_status;
	bool end_flag;
	bool conn_cancel;

	ovc_conn_params_t conn_params;

	enum OVC_CONN_STATE conn_state;
	enum OVPN_STATE ovpn_state;

	pthread_t pt_conn, pt_disconn;
	pthread_t pt_mon;

	int mgm_sock;
	int mgm_port;

	pid_t ovpn_pid;

	pthread_mutex_t conn_mt;

	char **cmd_args;
	int cmd_args_count;

	unsigned long bytes_in, bytes_out;
	char tun_ip[OVC_MAX_IPADDR];
	time_t connected_tm;

	struct ovc_ctx_priv *ctx;
} ovc_conn_mgr_t;

/*
 * init openvpn manager
 */

int ovc_init_ovpn(struct ovc_ctx_priv *ctx);

/*
 * finalize openvpn manager
 */

void ovc_finalize_ovpn(ovc_conn_mgr_t *conn_mgr);

/*
 * start openvpn connection
 */

int ovc_start_ovpn(ovc_conn_mgr_t *conn_mgr, const char *conn_json);

/*
 * stop openvpn connection
 */

int ovc_stop_ovpn(ovc_conn_mgr_t *conn_mgr, bool is_non_block);

#endif /* __LIBOVPN_OVPN_H__ */
