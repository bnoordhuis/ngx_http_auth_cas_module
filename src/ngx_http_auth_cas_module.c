#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>

#define CAS_SERVICE_PARAM  "?service="
#define CAS_COOKIE_NAME    "CASC"

typedef struct {
	/* CAS authentication required? */
	ngx_flag_t auth_cas;

	/* CAS authentication required? */
	ngx_flag_t auth_cas_validate;

	/* name of service ticket cookie */
	ngx_str_t auth_cas_cookie;

	/* CAS server login URL */
	ngx_str_t auth_cas_login_url;

	/* our base URL - don't reconstruct service URL from Host header, see https://wiki.jasig.org/display/CASC/CASFilter */
	ngx_str_t auth_cas_service_url;

	/* CAS server ticket validation URL (SAML and regular) */
	ngx_str_t auth_cas_validate_url;

	/* upstream config of the CAS server */
	ngx_http_upstream_conf_t *upstream;
} ngx_http_auth_cas_ctx_t;

ngx_module_t ngx_http_auth_cas_module;

static ngx_int_t ngx_http_auth_cas_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_process_header(ngx_http_request_t *r);
static void ngx_http_auth_cas_abort_request(ngx_http_request_t *r);
static void ngx_http_auth_cas_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_auth_cas_handler(ngx_http_request_t *r);

static int find_cookie(ngx_http_request_t *r, ngx_str_t name, ngx_str_t *value) {
	const ngx_table_elt_t *cookie = *(ngx_table_elt_t **) r->headers_in.cookies.elts;
	int nelts;

	for (nelts = r->headers_in.cookies.nelts; nelts > 0; nelts--, cookie++) {
		u_char *start = cookie->value.data;
		u_char *end   = cookie->value.data + cookie->value.len;

		while (start < end) {
			/* skip leading whitespace */
			while (isspace((*start))) start++;

			u_char *equals_sign = memchr(start, '=', end - start);
			if (equals_sign == NULL) {
				break;
			}

			u_char *val = equals_sign + 1;
			u_char *semicolon = memchr(val, ';', end - val);

			if ((size_t) (equals_sign - start) == name.len
				&& ngx_memcmp(start, name.data, name.len) == 0)
			{
				value->len = end - val;
				if (!semicolon) {
					value->data = val;
				} else {
					/* part of a "foo=42; bar=1337" string, make a copy */
					if (NULL == (value->data = ngx_pnalloc(r->pool, value->len + 1))) {
						return 0;
					}
					*(ngx_cpymem(value->data, val, value->len)) = '\0';
				}
				return 1;
			}

			if (semicolon) {
				start = semicolon + 1;
			} else {
				break;
			}
		}
	}

	return 0;
}

static ngx_int_t send_redirect(ngx_http_request_t *r, const ngx_str_t location) {
	ngx_table_elt_t *loc;

	loc = r->headers_out.location = ngx_list_push(&r->headers_out.headers);
	if (loc == NULL) {
		return NGX_ERROR;
	}

	loc->key.data = (u_char *) "Location";
	loc->key.len  = sizeof("Location") - 1;
	loc->value    = location;
	loc->hash     = 1;

	return NGX_HTTP_MOVED_TEMPORARILY;
}

static ngx_int_t send_reload(ngx_http_request_t *r) {
	ngx_str_t location;
	location.data = r->uri.data;
	location.len = r->uri.len + 1 + r->args.len;
	return send_redirect(r, location);
}

static ngx_int_t send_login_redirect(ngx_http_request_t *r) {
	const ngx_http_auth_cas_ctx_t *ctx = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	ngx_str_t location;

	location.len = ctx->auth_cas_login_url.len
			+ sizeof(CAS_SERVICE_PARAM)
			+ ctx->auth_cas_service_url.len
			+ (r->uri.len * 3)
			+ 3 /* %3F == '?' */
			+ (r->args.len * 3);

	location.data = ngx_pnalloc(r->pool, location.len);

	if (location.data == NULL) {
		return NGX_ERROR;
	}

	u_char *p = location.data;
	p = ngx_cpymem(p, ctx->auth_cas_login_url.data, ctx->auth_cas_login_url.len);
	p = ngx_cpymem(p, CAS_SERVICE_PARAM, sizeof(CAS_SERVICE_PARAM) - 1);
	p = ngx_cpymem(p, ctx->auth_cas_service_url.data, ctx->auth_cas_service_url.len);
	p = (u_char *) ngx_escape_uri(p, r->uri.data, r->uri.len + 1 + r->args.len, NGX_ESCAPE_ARGS);
	*p = '\0';

	location.len = p - location.data;

	return send_redirect(r, location);

}

/* is there a proxy or service ticket in the query string?
 * CAS tickets always starts with "PT-" or "ST-", see https://issues.jasig.org/browse/MAS-44
 */
static ngx_int_t scan_and_remove_ticket(ngx_http_request_t *r, ngx_str_t *ticket) {
	if (ngx_http_arg(r, (u_char *) "ticket", sizeof("ticket") - 1, ticket) == NGX_OK
		&& ticket->len > 3
		&& (ticket->data[0] == 'P' || ticket->data[0] == 'S')
		&& ticket->data[1] == 'T'
		&& ticket->data[2] == '-')
	{
		/* remove ticket from query string */
		if (r->args.data + r->args.len == ticket->data + ticket->len) {
			if (r->args.data == ticket->data) {
				/* only argument */
				r->args.len = 0;
			} else {
				/* last argument */
				r->args.len -= ticket->len + sizeof("ticket") + 1;	/* ?ticket= or &ticket= */
			}
		} else {
			/* move trailing arguments */
			u_char *src = ticket->data + ticket->len + 1;
			u_char *dst = ticket->data - sizeof("ticket");
			size_t size = (r->args.data + r->args.len) - src;
			r->args.len = ngx_cpymem(dst, src, size) - r->args.data;
		}

		return 1;
	}

	return 0;
}

static ngx_int_t ngx_http_auth_cas_create_request(ngx_http_request_t *r) {
	return NGX_ERROR;
}

static ngx_int_t ngx_http_auth_cas_reinit_request(ngx_http_request_t *r) {
	ngx_http_upstream_t *u = r->upstream;

	u->process_header = ngx_http_auth_cas_process_status_line;

	return NGX_ERROR;
}

static ngx_int_t ngx_http_auth_cas_process_status_line(ngx_http_request_t *r) {
	ngx_http_upstream_t *u = r->upstream;

	ngx_http_status_t status;
	ngx_memzero(&status, sizeof(status));

	ngx_int_t rc = ngx_http_parse_status_line(r, &u->buffer, &status);

	if (rc == NGX_AGAIN) {
		return rc;
	}

	if (rc == NGX_ERROR) {
		return NGX_ERROR;
	}

	fprintf(stderr, "status.code=%ld\n", status.code);

	u->process_header = ngx_http_auth_cas_process_header;

	return ngx_http_auth_cas_process_header(r);
}

static ngx_int_t ngx_http_auth_cas_process_header(ngx_http_request_t *r) {
	return NGX_ERROR;
}

static void ngx_http_auth_cas_abort_request(ngx_http_request_t *r) {
}

static void ngx_http_auth_cas_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
}

static ngx_int_t ngx_http_auth_cas_handler(ngx_http_request_t *r) {
	fputs(__func__, stderr);

	ngx_http_auth_cas_ctx_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	if (!mlcf->auth_cas_validate) {
		return NGX_DECLINED;
	}

	if (ngx_http_upstream_create(r)) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_http_set_ctx(r, "context comes here", ngx_http_auth_cas_module);

	ngx_http_upstream_t *u = r->upstream;
	if (u == NULL) {
		return NGX_ERROR;
	}

	u->conf = mlcf->upstream;

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;

	u->output.tag = (ngx_buf_tag_t) &ngx_http_auth_cas_module;

	u->create_request   = ngx_http_auth_cas_create_request;
	u->reinit_request   = ngx_http_auth_cas_reinit_request;
	u->process_header   = ngx_http_auth_cas_process_header;
	u->abort_request    = ngx_http_auth_cas_abort_request;
	u->finalize_request = ngx_http_auth_cas_finalize_request;

	ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	return NGX_DONE;
}

static char *set_auth_cas_service_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_auth_cas_ctx_t *ctx = conf;

	ngx_str_t *value = (ngx_str_t *) cf->args->elts + 1;

	/* URL-escape service URL */
	ctx->auth_cas_service_url.len = value->len + ngx_escape_uri(NULL, value->data, value->len, NGX_ESCAPE_ARGS);
	ctx->auth_cas_service_url.data = ngx_pcalloc(cf->pool, ctx->auth_cas_service_url.len + 1);
	ngx_escape_uri(ctx->auth_cas_service_url.data, value->data, value->len, NGX_ESCAPE_ARGS);

	return NGX_CONF_OK;
}

static char *set_auth_cas_validate_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_auth_cas_ctx_t *mlcf = conf;

	if (mlcf->upstream->upstream) {
		return "is duplicate";
	}

	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_auth_cas_handler;

	ngx_str_t *value = (ngx_str_t *) cf->args->elts + 1;
	ngx_str_set(value, "cas/validate");

	ngx_url_t u;
	ngx_memzero(&u, sizeof(u));

	u.url = *value;
	u.uri_part = 1;
	u.no_resolve = 1;
	u.default_port = 8080;

	mlcf->upstream->upstream = ngx_http_upstream_add(cf, &u, 0);

	if (mlcf->upstream->upstream == NULL) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static void *ngx_http_auth_cas_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cas_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(*ctx) + sizeof(*ctx->upstream));

	ngx_str_null(&ctx->auth_cas_validate_url);
	ngx_str_null(&ctx->auth_cas_service_url);
	ngx_str_null(&ctx->auth_cas_login_url);
	ngx_str_null(&ctx->auth_cas_cookie);

	ctx->auth_cas_validate = NGX_CONF_UNSET;
	ctx->auth_cas = NGX_CONF_UNSET;

	ctx->upstream = (void *) (ctx + 1);

	return ctx;
}

static char *ngx_http_auth_cas_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_auth_cas_ctx_t *prev = parent;
	ngx_http_auth_cas_ctx_t *conf = child;

	ngx_conf_merge_value(conf->auth_cas, prev->auth_cas, 0);
	ngx_conf_merge_value(conf->auth_cas_validate, prev->auth_cas_validate, 0);
	ngx_conf_merge_str_value(conf->auth_cas_cookie, prev->auth_cas_cookie, CAS_COOKIE_NAME);

	if (conf->auth_cas_login_url.data == NULL) {
		conf->auth_cas_login_url = prev->auth_cas_login_url;
	}

	if (conf->auth_cas_service_url.data == NULL) {
		conf->auth_cas_service_url = prev->auth_cas_service_url;
	}

	if (conf->auth_cas_validate_url.data == NULL) {
		conf->auth_cas_validate_url = prev->auth_cas_validate_url;
	}

	if (conf->upstream == NULL) {
		conf->upstream = prev->upstream;
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_cas_init(ngx_conf_t *cf) {
	ngx_http_core_main_conf_t *corecf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	ngx_http_handler_pt *handler = ngx_array_push(&corecf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (handler == NULL) {
		return NGX_ERROR;
	}

	*handler = ngx_http_auth_cas_handler;

	return NGX_OK;
}

static char *ngx_http_auth_cas_post_validate(ngx_conf_t *cf, void *post, void *data) {
	ngx_http_auth_cas_ctx_t *mlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_cas_module);

	if (mlcf->upstream->upstream) {
		return "is duplicate";
	}

	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_auth_cas_handler;

	ngx_str_t *value = (ngx_str_t *) cf->args->elts + 1;
	ngx_str_set(value, "cas/validate");

	ngx_url_t u;
	ngx_memzero(&u, sizeof(u));

	u.url = *value;
	u.uri_part = 1;
	u.no_resolve = 1;
	u.default_port = 8080;

	mlcf->upstream->upstream = ngx_http_upstream_add(cf, &u, 0);

	if (mlcf->upstream->upstream == NULL) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static ngx_conf_post_handler_pt ngx_http_auth_cas_post_validate_pt = ngx_http_auth_cas_post_validate;

static ngx_command_t commands[] = {
	{
		ngx_string("auth_cas"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas),
		NULL
	},
	{
		ngx_string("auth_cas_validate"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas_validate),
		&ngx_http_auth_cas_post_validate_pt
	},
	{
		ngx_string("auth_cas_cookie"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas_cookie),
		NULL
	},
	{
		ngx_string("auth_cas_validate_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		/*
		set_auth_cas_validate_url,
		*/
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas_validate_url),
		NULL
	},
	{
		ngx_string("auth_cas_service_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		set_auth_cas_service_url,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas_service_url),
		NULL
	},
	{
		ngx_string("auth_cas_login_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas_login_url),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ctx = {
	NULL,
	ngx_http_auth_cas_init,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_auth_cas_create_loc_conf,
	ngx_http_auth_cas_merge_loc_conf
};

ngx_module_t ngx_http_auth_cas_module = {
	NGX_MODULE_V1,
	&ctx,
	commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};
