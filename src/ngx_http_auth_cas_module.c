#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_str_t auth_cas;
	ngx_str_t auth_cas_login_url;
} ngx_http_auth_cas_ctx_t;

ngx_module_t ngx_http_auth_cas_module;

static ngx_int_t ngx_http_auth_cas_handler(ngx_http_request_t *r) {
	const ngx_http_auth_cas_ctx_t *ctx = ngx_http_get_module_loc_conf(r, ngx_http_auth_cas_module);

	if (!ctx->auth_cas.data) {
		return NGX_DECLINED;
	}

	return NGX_HTTP_UNAUTHORIZED;
}

static void *ngx_http_auth_cas_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cas_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
	ngx_str_null(&ctx->auth_cas_login_url);
	return ctx;
}

static char *ngx_http_auth_cas_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	const ngx_http_auth_cas_ctx_t *prev = parent;
	ngx_http_auth_cas_ctx_t *conf = child;

	if (conf->auth_cas.data == NULL) {
		conf->auth_cas = prev->auth_cas;
	}
	if (conf->auth_cas_login_url.data == NULL) {
		conf->auth_cas_login_url = prev->auth_cas_login_url;
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
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, auth_cas),
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
