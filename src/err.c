
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "util.h"

static char g_last_errmsg[OVC_MAX_ERR_MSG];

/*
 * set error message
 */

void ovc_set_errmsg(const char *err_msg)
{
	strlcpy(g_last_errmsg, err_msg, sizeof(g_last_errmsg));
}

/*
 * get last error message
 */

const char *ovc_get_errmsg(void)
{
	return g_last_errmsg;
}
