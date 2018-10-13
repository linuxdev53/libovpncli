#ifndef __LIBOVPN_UTIL_H__
#define __LIBOVPN_UTIL_H__

/* size bounded string copy function */
size_t strlcpy(char *dst, const char *src, size_t size);

/* size bounded string copy function */
size_t strlcat(char *dst, const char *src, size_t size);

/* get free listening port */
int get_free_listen_port(int start_port);

#endif /* __LIBOVPN_UTIL_H__ */
