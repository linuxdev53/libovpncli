
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "libovpncli.h"

#include "ctx.h"

/*
 * initialize libovpncli
 */

ovc_ctx_t *libovpncli_init(const char *config_json, ovc_notify_cb_t notify_cb)
{
	ovc_ctx_priv_t *priv_ctx;

	priv_ctx = ovc_ctx_init(config_json, notify_cb);
	if (!priv_ctx)
		return NULL;

	return (ovc_ctx_t *)priv_ctx;
}

/*
 * finalize libovpncli
 */

void libovpncli_finalize(ovc_ctx_t *ctx)
{
	ovc_ctx_finalize((ovc_ctx_priv_t *)ctx);
}

/*
 * start openvpn connection
 */

int libovpncli_start_conn(ovc_ctx_t *ctx, const char *conn_json)
{
	return ovc_start_conn((ovc_ctx_priv_t *)ctx, conn_json);
}

/*
 * stop openvpn connection
 */

int libovpncli_stop_conn(ovc_ctx_t *ctx)
{
	return ovc_stop_conn((ovc_ctx_priv_t *)ctx, false);
}

/*
 * retart openvpn client
 */

int libovpncli_restart_conn(ovc_ctx_t *ctx)
{
	return 0;
}

/*
 * get status
 */

int libovpncli_get_status(ovc_ctx_t *ctx, char **status_json)
{
	return 0;
}

/*
 * get error message
 */

const char *libovpncli_get_strerr(void)
{
	return NULL;
}