#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *create_main_conf(ngx_conf_t *cf) {
	return NULL;
}

static char *init_main_conf(ngx_conf_t *cf, void *conf) {
	return NULL;
}

static char *cas_login_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	return NULL;
}

static ngx_int_t postconfiguration(ngx_conf_t *cf) {
	return NGX_OK;
}

static ngx_command_t commands[] = {
	{
		.name   = ngx_string("cas_login_url"),
		.type   = NGX_MAIN_CONF | NGX_CONF_TAKE1,
		.set    = cas_login_url,
		.conf   = NGX_MAIN_CONF,
		.offset = 0,
		.post   = NULL

	},
	ngx_null_command
};

static ngx_http_module_t ctx = {
	.preconfiguration  = NULL,
	.postconfiguration = postconfiguration,
	.create_main_conf  = create_main_conf,
	.init_main_conf    = init_main_conf,
	.create_srv_conf   = NULL,
	.merge_srv_conf    = NULL,
	.create_loc_conf   = NULL,
	.merge_loc_conf    = NULL,
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
