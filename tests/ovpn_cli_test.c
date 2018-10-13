#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libovpncli.h"

/*
 * read file contents
 */

void read_file_contents(const char *file_path, char *buf, size_t buf_size)
{
	FILE *fp;
	ssize_t read_len;

	/* read JSON buffer */
	fp = fopen(file_path, "r");
	if (!fp) {
		fprintf(stderr, "Could not read a file '%s'\n", file_path);
		exit(-1);
	}

	read_len = fread(buf, 1, buf_size - 1, fp);
	if (read_len <= 0) {
		fprintf(stderr, "Invalid configuration file '%s'\n", file_path);
		fclose(fp);
		exit(-1);
	}
	buf[read_len] = '\0';
	fclose(fp);
}

/*
 * notify callback function
 */

static void notify_cb(const char *notify_json)
{
	fprintf(stdout, "Received notification '%s'\n", notify_json);
}

/*
 * main function
 */

int main(int argc, char *argv[])
{
	ovc_ctx_t *ctx;

	FILE *json_fp;

	char config_json[1024], conn_params_json[1024];
	int ret;

	/* check arguments */
	if (argc != 3) {
		fprintf(stderr, "ovpn_cli_test <JSON config file> <JSON connection params file>\n");
		exit(-1);
	}

	/* read JSON configuration and connection params */
	read_file_contents(argv[1], config_json, sizeof(config_json));
	read_file_contents(argv[2], conn_params_json, sizeof(conn_params_json));

	/* initialize libovpncli context */
	ctx = libovpncli_init(config_json, notify_cb);
	if (!ctx) {
		fprintf(stderr, "libovpncli_init() failed(err:%s)\n", libovpncli_get_strerr());
		exit(-1);
	}

	/* try to connect OpenVPN server */
	ret = libovpncli_start_conn(ctx, conn_params_json);
	if (ret == 0) {
		/* sleep for 30 seconds */
		sleep(30);

		/* stop OpenVPN conneciton */
		libovpncli_stop_conn(ctx);
	}

	/* finalize libovpncli context */
	libovpncli_finalize(ctx);

	return ret;
}
