
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

#include "jsonc-helper.h"
#include "ctx.h"

static ovc_logger_t *g_logger;

/*
 * initialize logger
 */

int ovc_init_logger(ovc_ctx_priv_t *ctx)
{
	g_logger = (ovc_logger_t *)malloc(sizeof(ovc_logger_t));
	if (!g_logger)
		return -1;

	g_logger->c = ctx;
	pthread_mutex_init(&g_logger->mt, NULL);

	return 0;
}

/*
 * finalize logger
 */

void ovc_finalize_logger(void)
{
	if (!g_logger)
		return;

	pthread_mutex_destroy(&g_logger->mt);
	free(g_logger);
}

/*
 * send notification for log message
 */

static void send_log_notify(enum OVC_LOG_TYPE log_type, const char *log_line)
{
	int notify_type = OVC_NOTIFY_TYPE_LOG;
	char *notify_str;

	jhelper_object_t log_jobjs[] = {
		{"type", JSON_TYPE_INT, false, &notify_type, 0},
		{"data", JSON_TYPE_STRING, false, (void *)log_line, 0}
	};

	if (!g_logger->c->notify_cb)
		return;

	if (!g_logger->c->ops.report_ovpn_log && log_type == OVC_LOG_TYPE_OVPN)
		return;

	/* build notification JSON string */
	if (jhelper_build_ex(log_jobjs, &notify_str) != 0)
		return;

	g_logger->c->notify_cb(notify_str);
	free(notify_str);
}

/*
 * write log line
 */

static const char *log_type_strs[] = {"INFO", "ERR", "WARN", "OVPN"};

void ovc_log(enum OVC_LOG_LEVEL log_level, enum OVC_LOG_TYPE log_type,
		const char *filename, int line, const char *format, ...)
{
	va_list va_args;
	char msg[OVC_MAX_LOG_MSG], log_line[OVC_MAX_LOG_MSG];

	time_t tt;
	struct tm *tm;
	char time_str[64];

	if (!g_logger)
		return;

	/* check log level */
	if (log_level > g_logger->c->ops.log_level)
		return;

	/* lock mutex */
	pthread_mutex_lock(&g_logger->mt);

	/* build log message */
	va_start(va_args, format);
	vsnprintf(msg, sizeof(msg), format, va_args);
	va_end(va_args);

	time(&tt);
	tm = localtime(&tt);

	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

	if (log_level == OVC_LOG_LEVEL_NORMAL)
		snprintf(log_line, sizeof(log_line), "%s|%s|%s", time_str, log_type_strs[log_type], msg);
	else
		snprintf(log_line, sizeof(log_line), "%s|%s|%s(at %s:%d)", time_str, log_type_strs[log_type],
			msg, filename, line);

	/* notify log line */
	send_log_notify(log_type, log_line);

	/* unlock mutex */
	pthread_mutex_unlock(&g_logger->mt);
}
