#ifndef __LIBOVPN_CLI_H__
#define __LIBOVPN_CLI_H__

typedef void *ovc_ctx_t;

/*
 * libovpncli notification callback function
 */

typedef void (*ovc_notify_cb_t)(const char *notify_json);

/*
 * libovpncli notification type
 */

enum OVC_NOTIFY_TYPES {
	OVC_NOTIFY_TYPE_STATE = 0,
	OVC_NOTIFY_TYPE_LOG,
	OVC_NOTIFY_TYPE_BYTECOUNT,
};

/*
 * libovpncli error codes
 */

enum OVC_ERR_CODES {
	OVC_ERR_OK = 0,
	OVC_ERR_INVALID_CONFIG,
	OVC_ERR_OUT_MEM,
};

/*
 * initialize libovpncli
 */

ovc_ctx_t *libovpncli_init(const char *config_json, ovc_notify_cb_t notify_cb);

/*
 * finalize libovpncli
 */

void libovpncli_finalize(ovc_ctx_t *ctx);

/*
 * start openvpn client
 */

int libovpncli_start_conn(ovc_ctx_t *ctx, const char *conn_json);

/*
 * stop openvpn client
 */

int libovpncli_stop_conn(ovc_ctx_t *ctx);

/*
 * retart openvpn client
 */

int libovpncli_restart_conn(ovc_ctx_t *ctx);

/*
 * get status
 */

int libovpncli_get_status(ovc_ctx_t *ctx, char **status_json);

/*
 * get error message
 */

const char *libovpncli_get_strerr(void);

#endif /* __LIBOVPN_CLI_H__ */
