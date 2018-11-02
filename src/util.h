#ifndef __LIBOVPN_UTIL_H__
#define __LIBOVPN_UTIL_H__

/* size bounded string copy function */
size_t strlcpy(char *dst, const char *src, size_t size);

/* size bounded string copy function */
size_t strlcat(char *dst, const char *src, size_t size);

/* get free listening port */
int get_free_listen_port(int start_port);

/* build the arguments for command line */
int add_cmdline_args(char ***args, int *args_count, const char *fmt, ...);

/* get token by given character */
void get_token_by_char(char **pp, char sep, char *token, size_t size);

#endif /* __LIBOVPN_UTIL_H__ */
