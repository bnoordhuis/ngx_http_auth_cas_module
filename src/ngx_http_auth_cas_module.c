#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_str_t cas_login_url;
} ngx_http_auth_cas_ctx_t;

static void *ngx_http_auth_cas_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cas_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
	ngx_str_null(&ctx->cas_login_url);
	return ctx;
}

static char *ngx_http_auth_cas_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	const ngx_http_auth_cas_ctx_t *prev = (ngx_http_auth_cas_ctx_t *) parent;
	ngx_http_auth_cas_ctx_t *conf = (ngx_http_auth_cas_ctx_t *) child;

	if (conf->cas_login_url.data == NULL) {
		conf->cas_login_url = prev->cas_login_url;
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_cas_init(ngx_conf_t *cf) {
	return NGX_OK;
}

static ngx_command_t commands[] = {
	{
		ngx_string("cas_login_url"),
		NGX_HTTP_MAIN_CONF |NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cas_ctx_t, cas_login_url),
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
