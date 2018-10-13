#ifndef __LIBOVPNCLI_LOG_H__
#define __LIBOVPNCLI_LOG_H__

/*
 * verbosity level
 */

enum OVC_LOG_LEVEL {
	OVC_LOG_LEVEL_NORMAL = 0,
	OVC_LOG_LEVEL_DEBUG,
	OVC_LOG_LEVEL_VERBOSE
};

/*
 * log type
 */

enum OVC_LOG_TYPE {
	OVC_LOG_TYPE_INFO,
	OVC_LOG_TYPE_ERR,
	OVC_LOG_TYPE_WARN,
	OVC_LOG_TYPE_OVPN
};

#define OVC_DEBUG_MSG(level, ...)          ovc_log(level, OVC_LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define OVC_DEBUG_ERR(level, ...)          ovc_log(level, OVC_LOG_TYPE_ERR, __FILE__, __LINE__, __VA_ARGS__);
#define OVC_DEBUG_WARN(level, ...)         ovc_log(level, OVC_LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);

/*
 * logger structure
 */

typedef struct ovc_logger {
	struct ovc_ctx_priv *c;
	pthread_mutex_t mt;
} ovc_logger_t;

/*
 * initialize logger
 */

int ovc_init_logger(struct ovc_ctx_priv *ctx);

/*
 * finalize logger
 */

void ovc_finalize_logger(void);

/*
 * write log line
 */

void ovc_log(enum OVC_LOG_LEVEL log_level, enum OVC_LOG_TYPE log_type,
		const char *filename, int line, const char *format, ...);

#endif /* __LIBOVPNCLI_LOG_H__ */
