#ifndef __LIBOVPN_CTX_H__
#define __LIBOVPN_CTX_H__

struct ovc_ctx_priv;

#include "common.h"
#include "util.h"
#include "err.h"
#include "log.h"
#include "ovpn.h"
#include "libovpncli.h"

/*
 * default JSON configuration values
 */

#define OVC_DEFAULT_LOG_LEVEL             OVC_LOG_LEVEL_NORMAL

/*
 * libovpncli options
 */

typedef struct ovc_options {
	bool enable_log;
	enum OVC_LOG_LEVEL log_level;

	char ovpn_bin_path[OVC_MAX_PATH];
	bool report_ovpn_log;
	bool report_byte_count;
} ovc_options_t;

/*
 * libovpncli context object
 */

typedef struct ovc_ctx_priv {
	ovc_options_t ops;

	ovc_notify_cb_t notify_cb;
	ovc_conn_mgr_t conn_mgr;
} ovc_ctx_priv_t;

/*
 * libovpncli context API functions
 */

ovc_ctx_priv_t *ovc_ctx_init(const char *config_json, ovc_notify_cb_t notify_cb);
void ovc_ctx_finalize(ovc_ctx_priv_t *ctx);

int ovc_start_conn(ovc_ctx_priv_t *ctx, const char *conn_json);
int ovc_stop_conn(ovc_ctx_priv_t *ctx, bool is_non_block);

#endif /* __LIBOVPN_CTX_H__ */
