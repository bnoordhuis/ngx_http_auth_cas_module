#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>

#define CAS_SERVICE_PARAM  "?service="
#define CAS_COOKIE_NAME    "CASC"

typedef struct {
	/* CAS authentication required? */
	ngx_flag_t auth_cas;

	/* name of service ticket cookie */
	ngx_str_t auth_cas_cookie;

	/* CAS server login URL */
	ngx_str_t auth_cas_login_url;

	/* our base URL - don't reconstruct service URL from Host header, see https://wiki.jasig.org/display/CASC/CASFilter */
	ngx_str_t auth_cas_service_url;

	/* CAS server ticket validation URL (SAML and regular) */
	ngx_str_t auth_cas_validate_url;
} ngx_http_auth_cas_ctx_t;

ngx_module_t ngx_http_auth_cas_module;

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
	if (NULL == (r->headers_out.location = ngx_list_push(&r->headers_out.headers))) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.location->hash = 1;
	r->headers_out.location->value = location;
	ngx_str_set(&r->headers_out.location->key, "Location");

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

	if (!location.data) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cas_reinit_request(ngx_http_request_t *r) {
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cas_process_header(ngx_http_request_t *r) {
	return NGX_OK;
}

static void ngx_http_auth_cas_abort_request(ngx_http_request_t *r) {
}

static void ngx_http_auth_cas_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
	send_reload(r);
}

static ngx_int_t ngx_http_auth_cas_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
	u_char chunk[1 + (buf->last - buf->start)];
	*(ngx_cpymem(chunk, buf->start, buf->last - buf->start)) = '\0';
	fprintf(stderr, "chunk: %s\n", chunk);
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cas_handler(ngx_http_request_t *r) {
	const ngx_http_auth_cas_ctx_t *ctx = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	if (!ctx->auth_cas) {
		return NGX_DECLINED;
	}

	ngx_str_t ticket = ngx_null_string;

	if (scan_and_remove_ticket(r, &ticket)) {
		if (ngx_http_upstream_create(r) != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_http_upstream_t *u = r->upstream;

		/* TODO append service and ticket parameters */
		u->uri = ctx->auth_cas_validate_url;

		u->method.len = sizeof("POST") - 1;
		u->method.data = (u_char *) "POST";

		u->output.tag = (ngx_buf_tag_t) &ngx_http_auth_cas_module;
		u->create_request   = ngx_http_auth_cas_create_request;
		u->reinit_request   = ngx_http_auth_cas_reinit_request;
		u->process_header   = ngx_http_auth_cas_process_header;
		u->abort_request    = ngx_http_auth_cas_abort_request;
		u->finalize_request = ngx_http_auth_cas_finalize_request;

		u->pipe->input_filter = ngx_http_auth_cas_input_filter;
		ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

		if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
			return rc;
		}

		return NGX_DONE;
	}

	ngx_str_t cookie = ngx_null_string;

	if (!find_cookie(r, ctx->auth_cas_cookie, &cookie)) {
		return send_login_redirect(r);
	}

	return NGX_HTTP_UNAUTHORIZED;
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

static void *ngx_http_auth_cas_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cas_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));

	ctx->auth_cas = NGX_CONF_UNSET;
	ngx_str_null(&ctx->auth_cas_login_url);
	ngx_str_null(&ctx->auth_cas_service_url);
	ngx_str_null(&ctx->auth_cas_cookie);

	return ctx;
}

static char *ngx_http_auth_cas_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	const ngx_http_auth_cas_ctx_t *prev = parent;
	ngx_http_auth_cas_ctx_t *conf = child;

	ngx_conf_merge_value(conf->auth_cas, prev->auth_cas, 0);
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
