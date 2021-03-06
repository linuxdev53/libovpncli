
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "common.h"

/* size bounded string copy function */
size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t srclen;

	/* decrease size value */
	size--;

	/* get source len */
	srclen = strlen(src);
	if (srclen > size)
		srclen = size;

	memcpy(dst, src, srclen);
	dst[srclen] = '\0';

	return srclen;
}

/* size bounded string copy function */
size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t srclen;
	size_t dstlen;

	/* set length of destination buffer */
	dstlen = strlen(dst);
	size -= dstlen + 1;
	if (!size)
		return dstlen;

	/* get the length of source buffer */
	srclen = strlen(src);
	if (srclen > size)
		srclen = size;

	memcpy(dst + dstlen, src, srclen);
	dst[dstlen + srclen] = '\0';

	return (dstlen + srclen);
}

/* get free listening port */
int get_free_listen_port(int start_port)
{
	int sock;
	int listen_port = start_port;

	int ret = -1;

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;

	while (listen_port < 65535) {
		struct sockaddr_in listen_addr;

		/* set listen address */
		memset(&listen_addr, 0, sizeof(listen_addr));

		listen_addr.sin_family = AF_INET;
#ifdef WIN32
		listen_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
#else
		inet_pton(AF_INET, "127.0.0.1", &listen_addr.sin_addr);
#endif
		listen_addr.sin_port = htons(listen_port);

		/* try to bind on listen address */
		if (bind(sock, (struct sockaddr *)&listen_addr, sizeof(struct sockaddr_in)) == 0) {
			ret = 0;
			break;
		}
		listen_port++;
	}

#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif

	return (ret == 0) ? listen_port : -1;
}

/* build the arguments for command line */
void add_cmdline_args(char ***args, int *args_count, const char *fmt, ...)
{
	char **p = *args;
	int count = *args_count;

	va_list va_args;
	char cmdline[OVC_MAX_CMDLINE];

	char *tok, *rest;

	/* get whole command line string */
	va_start(va_args, fmt);
	vsnprintf(cmdline, sizeof(cmdline), fmt, va_args);
	va_end(va_args);

	/* split arguments by space */
	for (tok = strtok_r(cmdline, " ", &rest); tok != NULL;
		 tok = strtok_r(NULL, " ", &rest)) {
		if (isspace(*tok))
			continue;

		p = realloc(p, (count + 1) * sizeof(char *));
		if (!p)
			return;
		p[count++] = strdup(tok);
	}

	/* fill NULL to tail */
	p = realloc(p, (count + 1) * sizeof(char *));
	p[count] = NULL;

	*args = p;
	*args_count = count;
}

/* get token by given character */
void get_token_by_char(char **pp, char sep, char *token, size_t size)
{
	char *p = *pp;
	int i = 0;

	/* set buffer until comma is exist */
	while (*p != sep && *p != '\0' && *p != '\n' && !isspace(*p)) {
		if (size > 0 && (i == (int) (size - 1)))
			break;

		if (token)
			token[i++] = *p;
		p++;
	}

	if (token)
		token[i] = '\0';

	if (*p != '\0')
		*pp = p + 1;
}
