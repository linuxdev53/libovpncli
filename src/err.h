#ifndef __LIBOVPNCLI_ERR_H__
#define __LIBOVPNCLI_ERR_H__

/*
 * set error message
 */

void ovc_set_errmsg(const char *err_msg);

/*
 * get last error message
 */

const char *ovc_get_errmsg(void);

#endif /* __LIBOVPNCLI_ERR_H__ */
