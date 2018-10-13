
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "jsonc-helper.h"

#include "libovpncli.h"

#include "ctx.h"

/*
 * init context object
 */

static int parse_options(ovc_ctx_priv_t *ctx, const char *config_json)
{
	ovc_options_t *ops = &ctx->ops;

	jhelper_object_t ovc_opts[] = {
		{"enable_log", JSON_TYPE_BOOL, false, &ops->enable_log},
		{"log_level", JSON_TYPE_INT, false, &ops->log_level},
		{"openvpn_path", JSON_TYPE_STRING, true, &ops->ovpn_bin_path},
		{"report_ovpn_log", JSON_TYPE_BOOL, false, &ops->report_ovpn_log},
		{"report_byte_count", JSON_TYPE_BOOL, false, &ops->report_byte_count}
	};

	/* init context options */
	ops->enable_log = true;
	ops->log_level = OVC_LOG_LEVEL_NORMAL;
	ops->report_ovpn_log = true;
	ops->report_byte_count = false;

	/* parse JSON configuration */
	if (jhelper_parse_ex(config_json, ovc_opts) != 0) {
		fprintf(stderr, "Invalid JSON config data '%s'\n", config_json);
		return -1;
	}

	ctx->opt_data = ovc_opts;
	ctx->opt_count = sizeof(ovc_opts) / sizeof(jhelper_object_t);

	return 0;
}

/*
 * free context object
 */

static void free_ctx(ovc_ctx_priv_t *ctx)
{
	jhelper_free((jhelper_object_t *)ctx->opt_data, ctx->opt_count);
	free(ctx);
}

/*
 * initialize libovpncli context
 */

ovc_ctx_priv_t *ovc_ctx_init(const char *config_json, ovc_notify_cb_t notify_cb)
{
	ovc_ctx_priv_t *ctx;

	/* allocate and init context object */
	ctx = (ovc_ctx_priv_t *)malloc(sizeof(ovc_ctx_priv_t));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(ovc_ctx_priv_t));

	/* parse options */
	if (parse_options(ctx, config_json) != 0) {
		ovc_set_errmsg("Invalid JSON configuration\n");

		free(ctx);
		return NULL;
	}
	ctx->notify_cb = notify_cb;

	/* init logger */
	if (ovc_init_logger(ctx) != 0)
		goto end;

	OVC_DEBUG_MSG(0, "Initializing libovpncli context");

	/* init VPN connection manager */
	if (ovc_init_ovpn(ctx) != 0)
		goto end;

	return ctx;

end:
	free_ctx(ctx);

	return NULL;
}

/*
 * finalize libovpncli context
 */

void ovc_ctx_finalize(ovc_ctx_priv_t *ctx)
{
	OVC_DEBUG_MSG(0, "Finalizing libovpncli context");

	/* finalize openvpn connection manager */
	ovc_finalize_ovpn(&ctx->conn_mgr);

	/* finalize logger */
	ovc_finalize_logger();

	/* free context object */
	free_ctx(ctx);
}

/*
 * start OpenVPN connection
 */

int ovc_start_conn(ovc_ctx_priv_t *ctx, const char *conn_json)
{
	return ovc_start_ovpn(&ctx->conn_mgr, conn_json);
}

/*
 * stop OpenVPN connection
 */

int ovc_stop_conn(ovc_ctx_priv_t *ctx)
{
	return ovc_stop_ovpn(&ctx->conn_mgr);
}
