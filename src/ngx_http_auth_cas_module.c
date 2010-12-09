#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>

#include <expat.h>

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

	/* upstream config of the CAS server */
	ngx_http_upstream_conf_t upstream;
} ngx_http_auth_cas_loc_conf_t;

/* used when validating a service ticket */
typedef struct {
	ngx_http_status_t status;

	/* SAX parser for the SAML response */
	XML_Parser parser;
} ngx_http_auth_cas_validation_ctx_t;

ngx_module_t ngx_http_auth_cas_module;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_auth_cas_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_process_header(ngx_http_request_t *r);
static void ngx_http_auth_cas_abort_request(ngx_http_request_t *r);
static void ngx_http_auth_cas_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static void *ngx_http_auth_cas_create_upstream(ngx_conf_t *cf, ngx_http_auth_cas_loc_conf_t *conf);
static char *ngx_http_auth_cas_merge_upstream(ngx_conf_t *cf, ngx_http_auth_cas_loc_conf_t *prev, ngx_http_auth_cas_loc_conf_t *conf);

static ngx_int_t ngx_http_auth_cas_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cas_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

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
	const ngx_http_auth_cas_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	ngx_str_t location;

	location.len = mlcf->auth_cas_login_url.len
			+ sizeof(CAS_SERVICE_PARAM)
			+ mlcf->auth_cas_service_url.len
			+ (r->uri.len * 3)
			+ 3 /* %3F == '?' */
			+ (r->args.len * 3);

	location.data = ngx_pnalloc(r->pool, location.len);

	if (location.data == NULL) {
		return NGX_ERROR;
	}

	u_char *p = location.data;
	p = ngx_cpymem(p, mlcf->auth_cas_login_url.data, mlcf->auth_cas_login_url.len);
	p = ngx_cpymem(p, CAS_SERVICE_PARAM, sizeof(CAS_SERVICE_PARAM) - 1);
	p = ngx_cpymem(p, mlcf->auth_cas_service_url.data, mlcf->auth_cas_service_url.len);
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
	/* TODO create a real request */
#define CASC_REQUEST \
	"GET /validate?service=http://localhost:8081/protected/&ticket=ST-1337 HTTP/1.0" CRLF \
	"Host: localhost:8080" CRLF \
	CRLF

	ngx_buf_t *b = ngx_create_temp_buf(r->pool, sizeof(CASC_REQUEST) - 1);
	if (b == NULL) {
		return NGX_ERROR;
	}

	b->pos = (u_char *) CASC_REQUEST;
	b->last = b->pos + sizeof(CASC_REQUEST) - 1;

	ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	cl->buf = b;
	cl->next = NULL;

	r->upstream->request_bufs = cl;

	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cas_reinit_request(ngx_http_request_t *r) {
	r->upstream->process_header = ngx_http_auth_cas_process_status_line;
	r->state = 0;

	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cas_process_status_line(ngx_http_request_t *r) {
	ngx_http_auth_cas_validation_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cas_module);

	ngx_http_upstream_t *u = r->upstream;

	ngx_int_t rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
	if (rc == NGX_AGAIN || rc == NGX_ERROR) {
		return rc;
	}

	u->headers_in.status_n = ctx->status.code;

	u->process_header = ngx_http_auth_cas_process_header;

	return ngx_http_auth_cas_process_header(r);
}

static ngx_int_t ngx_http_auth_cas_process_header(ngx_http_request_t *r) {
	while (1) {
		ngx_int_t rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

		if (rc == NGX_OK) {
			continue;
		}

		if (rc == NGX_AGAIN) {
			return NGX_AGAIN;
		}

		if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
			return NGX_OK;
		}

		return NGX_HTTP_UPSTREAM_INVALID_HEADER;
	}
}

static void ngx_http_auth_cas_abort_request(ngx_http_request_t *r) {
}

static void ngx_http_auth_cas_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
}

static ngx_int_t ngx_http_auth_cas_header_filter(ngx_http_request_t *r) {
	return ngx_http_next_header_filter(r);
}

static const char *cstring(ngx_http_request_t *r, u_char *first, u_char *last) {
	size_t size = 1 + (last - first);

	u_char *s = ngx_palloc(r->pool, size);
	if (s != NULL) {
		*(ngx_cpymem(s, first, size)) = '\0';
	}

	return (const char *) s;
}

static ngx_int_t ngx_http_auth_cas_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
	ngx_http_auth_cas_validation_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cas_module);

	if (ctx == NULL || in == NULL) {
		return ngx_http_next_body_filter(r, in);
	}

	ngx_buf_t *b = in->buf;

	if (b->pos) {
		fprintf(stderr, "%ld bytes of data: %s\n", b->last - b->pos, cstring(r, b->pos, b->last));

		if (XML_Parse(ctx->parser, (const char *) b->pos, b->last - b->pos, 0) == XML_STATUS_ERROR) {
			fprintf(stderr, "XML parse error: %s\n",
				XML_ErrorString(XML_GetErrorCode(ctx->parser)));

			/* XXX maybe add an error flag to ngx_http_auth_cas_validation_ctx_t? */
			ngx_http_set_ctx(r, NULL, ngx_http_auth_cas_module);
		}

		/* cheap hack to prevent the upstream response from being sent to the client,
		 * nginx doesn't like empty buffers so leave in a single newline
		 */
		b->pos = (u_char *) "\n";
		b->last = b->pos + 1;
	}

	return ngx_http_next_body_filter(r, in);
}

static void ngx_http_auth_cas_validation_cleanup(void *data) {
	ngx_http_auth_cas_validation_ctx_t *ctx = data;

	XML_ParserFree(ctx->parser);
}

static ngx_int_t ngx_http_auth_cas_handler(ngx_http_request_t *r) {
	ngx_http_auth_cas_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	if (!mlcf->auth_cas) {
		return NGX_DECLINED;
	}

	if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* contains the state machine that parses the CAS server response */
	ngx_http_auth_cas_validation_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(*ctx));

	ctx->parser = XML_ParserCreateNS(NULL, '\0');

	ngx_pool_cleanup_t *cleanup = ngx_pool_cleanup_add(r->pool, 0);
	if (cleanup == NULL) {
		return NGX_ERROR;
	}

	cleanup->handler = ngx_http_auth_cas_validation_cleanup;
	cleanup->data = ctx;

	ngx_http_set_ctx(r, ctx, ngx_http_auth_cas_module);

	ngx_http_upstream_t *u = r->upstream;
	if (u == NULL) {
		return NGX_ERROR;
	}

	u->conf = &mlcf->upstream;

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;

	u->output.tag = (ngx_buf_tag_t) &ngx_http_auth_cas_module;

	u->create_request   = ngx_http_auth_cas_create_request;
	u->reinit_request   = ngx_http_auth_cas_reinit_request;
	u->process_header   = ngx_http_auth_cas_process_status_line;
	u->abort_request    = ngx_http_auth_cas_abort_request;
	u->finalize_request = ngx_http_auth_cas_finalize_request;

	ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	return NGX_DONE;
}

static char *set_auth_cas_service_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_auth_cas_loc_conf_t *mlcf = conf;

	ngx_str_t *value = (ngx_str_t *) cf->args->elts + 1;

	/* URL-escape service URL */
	mlcf->auth_cas_service_url.len = value->len + ngx_escape_uri(NULL, value->data, value->len, NGX_ESCAPE_ARGS);
	mlcf->auth_cas_service_url.data = ngx_pcalloc(cf->pool, mlcf->auth_cas_service_url.len + 1);
	ngx_escape_uri(mlcf->auth_cas_service_url.data, value->data, value->len, NGX_ESCAPE_ARGS);

	return NGX_CONF_OK;
}

/* taken nearly verbatim from ngx_http_proxy_create_loc_conf() in ngx_http_proxy_module.c */
static void *ngx_http_auth_cas_create_upstream(ngx_conf_t *cf, ngx_http_auth_cas_loc_conf_t *conf) {
    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->method = NULL;
     *     conf->headers_source = NULL;
     *     conf->headers_set_len = NULL;
     *     conf->headers_set = NULL;
     *     conf->headers_set_hash = NULL;
     *     conf->body_set_len = NULL;
     *     conf->body_set = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;
#if (NGX_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    return conf;
}

static ngx_path_init_t  ngx_http_proxy_temp_path = {
	ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};

/* taken nearly verbatim from ngx_http_proxy_merge_loc_conf() in ngx_http_proxy_module.c */
static char *ngx_http_auth_cas_merge_upstream(ngx_conf_t *cf, ngx_http_auth_cas_loc_conf_t *prev, ngx_http_auth_cas_loc_conf_t *conf) {
	size_t size;

    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        if (conf->upstream.store_lengths == NULL) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 1000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 1000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 1000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_proxy_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


#if (NGX_HTTP_CACHE)

    ngx_conf_merge_ptr_value(conf->upstream.cache,
                              prev->upstream.cache, NULL);

    if (conf->upstream.cache && conf->upstream.cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    if (conf->upstream.no_cache && conf->upstream.cache_bypass == NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
             "\"proxy_no_cache\" functionality has been changed in 0.8.46, "
             "now it should be used together with \"proxy_cache_bypass\"");
    }

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NGX_HTTP_SSL)
    ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);
#endif

    return NGX_CONF_OK;
}

static void *ngx_http_auth_cas_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cas_loc_conf_t *mlcf = ngx_pcalloc(cf->pool, sizeof(*mlcf));

	ngx_str_null(&mlcf->auth_cas_validate_url);
	ngx_str_null(&mlcf->auth_cas_service_url);
	ngx_str_null(&mlcf->auth_cas_login_url);
	ngx_str_null(&mlcf->auth_cas_cookie);
	mlcf->auth_cas = NGX_CONF_UNSET;

	return ngx_http_auth_cas_create_upstream(cf, mlcf);
}


static char *ngx_http_auth_cas_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_auth_cas_loc_conf_t *prev = parent;
	ngx_http_auth_cas_loc_conf_t *conf = child;

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

	if (conf->upstream.upstream == NULL) {
		conf->upstream.upstream = prev->upstream.upstream;
	}

	return ngx_http_auth_cas_merge_upstream(cf, prev, conf);
}

static ngx_int_t ngx_http_auth_cas_init(ngx_conf_t *cf) {
	ngx_http_core_main_conf_t *corecf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	ngx_http_handler_pt *handler = ngx_array_push(&corecf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (handler == NULL) {
		return NGX_ERROR;
	}

	*handler = ngx_http_auth_cas_handler;

	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_auth_cas_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_auth_cas_body_filter;

	return NGX_OK;
}

static char *ngx_http_auth_cas_validate_url_post(ngx_conf_t *cf, void *post, void *data) {
	ngx_http_auth_cas_loc_conf_t *mlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_cas_module);

	if (mlcf->upstream.upstream) {
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

	mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);

	if (mlcf->upstream.upstream == NULL) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static ngx_conf_post_handler_pt ngx_http_auth_cas_validate_url_post_pt = ngx_http_auth_cas_validate_url_post;

static ngx_command_t ngx_http_auth_cas_commands[] = {
	{
		ngx_string("auth_cas"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_loc_conf_t, auth_cas),
		NULL
	},
	{
		ngx_string("auth_cas_cookie"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_loc_conf_t, auth_cas_cookie),
		NULL
	},
	{
		ngx_string("auth_cas_validate_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_loc_conf_t, auth_cas_validate_url),
		&ngx_http_auth_cas_validate_url_post_pt
	},
	{
		ngx_string("auth_cas_service_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		set_auth_cas_service_url,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_loc_conf_t, auth_cas_service_url),
		NULL
	},
	{
		ngx_string("auth_cas_login_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_loc_conf_t, auth_cas_login_url),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_auth_cas_ctx = {
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
	&ngx_http_auth_cas_ctx,
	ngx_http_auth_cas_commands,
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
