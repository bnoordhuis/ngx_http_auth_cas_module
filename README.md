# ngx_http_auth_cas_module

This is a [nginx](http://nginx.org/) client for [JA-SIG CAS](http://www.jasig.org/cas), a popular enterprise single sign-on solution.

## Compiling

nginx does not support dynamic loading of modules so you need to add this module to nginx's build time dependencies.

	cd /path/to/nginx-source
	./configure --add-module=/path/to/ngx_http_auth_cas_module
	make install

## Configuration

This module is undergoing active development and its configuration options haven't quite stabilized yet.
