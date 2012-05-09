/*
**  mod_v8.cpp -- Apache v8 module
**
**  Then activate it in Apache's httpd.conf file:
**
**    # httpd.conf
**    LoadModule v8_module modules/mod_v8.so
**    AddHandler v8-script .v8
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* v8.hpp */
#include "v8.hpp"

/* httpd */
#ifdef __cplusplus
extern "C" {
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apreq2/apreq_module_apache2.h"
#ifdef __cplusplus
}
#endif

#define V8_CONTENT_TYPE "text/plain; charset=UTF-8";

#ifdef AP_V8_DEBUG_LOG_LEVEL
#define V8_DEBUG_LOG_LEVEL AP_V8_DEBUG_LOG_LEVEL
#else
#define V8_DEBUG_LOG_LEVEL APLOG_DEBUG
#endif

#define _RERR(r, format, args...)                                   \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                        \
                  r, "%s(%d) "format, __FILE__, __LINE__, ##args);
#define _SERR(s, format, args...)                                  \
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0,                        \
                 s, "%s(%d) "format, __FILE__, __LINE__, ##args);
#define _PERR(p, format, args...)                                   \
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0,                        \
                  p, "%s(%d) "format, __FILE__, __LINE__, ##args);
#define _RDEBUG(r, format, args...)                                     \
    ap_log_rerror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  r, "[V8_DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                     \
                 s, "[V8_DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);
#define _PDEBUG(p, format, args...)                                     \
    ap_log_perror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  p, "[V8_DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);

/* v8 server config */
typedef struct {
    v8::Isolate *isolate;
    V8::js *js;
} v8_server_config_t;

/* Functions */
static void *v8_create_server_config(apr_pool_t *p, server_rec *s);
static void v8_child_init(apr_pool_t *p, server_rec *s);
static int v8_handler(request_rec* r);

/* Commands */
static const command_rec v8_cmds[] =
{
    { NULL, NULL, NULL, 0, TAKE1, NULL }
};

/* Hooks */
static void v8_register_hooks(apr_pool_t *p)
{
    ap_hook_child_init(v8_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(v8_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module */
#ifdef __cplusplus
extern "C" {
#endif
module AP_MODULE_DECLARE_DATA v8_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    v8_create_server_config,    /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    v8_cmds,                    /* table of config file commands       */
    v8_register_hooks           /* register hooks                      */
};
#ifdef __cplusplus
}
#endif

/* read file */
static apr_status_t v8_read_file(const char *path, const char **out,
                                 apr_size_t *outlen, apr_pool_t *p,
                                 apr_pool_t *ptemp)
{
    char *c;
    apr_size_t len = 0;
    apr_status_t rv;
    apr_file_t *fp;
    apr_finfo_t fi;

    *out = NULL;
    *outlen = 0;

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY|APR_BUFFERED,
                       APR_OS_DEFAULT, ptemp);
    if (rv != APR_SUCCESS) {
        _PERR(p, "v8: file open: %s", path);
        return rv;
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS) {
        _PERR(p, "v8: file info get: %s", path);
        return rv;
    }

    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(ptemp);
    apr_bucket_brigade *bb = apr_brigade_create(ptemp, ba);

    apr_brigade_insert_file(bb, fp, 0, fi.size, ptemp);

    rv = apr_brigade_pflatten(bb, &c, &len, p);
    if (rv) {
        _PERR(p, "v8: apr_brigade_pflatten: %s", path);
        return rv;
    }

    *out = c;
    *outlen = len;

    return APR_SUCCESS;
}

/* V8::js cleanup */
static apr_status_t v8_js_cleanup(void *parms)
{
    v8_server_config_t *config = (v8_server_config_t *)parms;

    if (config->js) {
        delete config->js;
    }

#ifdef AP_USE_V8_ISOLATE
    if (config->isolate) {
        config->isolate->Exit();
        config->isolate->Dispose();
    }
#endif

    return APR_SUCCESS;
}

/* create server config */
static void *v8_create_server_config(apr_pool_t *p, server_rec *s)
{
    v8_server_config_t *config =
        (v8_server_config_t *)apr_pcalloc(p, sizeof(v8_server_config_t));

    config->js = NULL;

    return (void *)config;
}

/* child init */
static void v8_child_init(apr_pool_t *p, server_rec *s)
{
    v8_server_config_t *config =
        (v8_server_config_t *)ap_get_module_config(s->module_config, &v8_module);

#ifdef AP_USE_V8_ISOLATE
    config->isolate = v8::Isolate::New();
    config->isolate->Enter();
    config->isolate = v8::Isolate::GetCurrent();
    _PDEBUG(p, "isolate: enabled");
#endif

    config->js = new V8::js();
    apr_pool_cleanup_register(p, (void *)config,
                              v8_js_cleanup, apr_pool_cleanup_null);
}

/* content handler */
static int v8_handler(request_rec *r)
{
    int retval = OK;

    if (strcmp(r->handler, "v8-script")) {
        return DECLINED;
    }

    v8_server_config_t *config =
        (v8_server_config_t *)ap_get_module_config(r->server->module_config,
                                                   &v8_module);

    /* content type */
    r->content_type = V8_CONTENT_TYPE;

    if (!r->header_only) {
        //Request parameters.
        apreq_handle_t *apreq = apreq_handle_apache2(r);
        apr_table_t *params = apreq_params(apreq, r->pool);

        //Set ap internal fields.
        config->js->ap->SetInternalField(0, v8::External::New(r));
        config->js->ap->SetInternalField(1, v8::External::New(params));

        //Create a string containing the JavaScript source code.
        const char *src;
        apr_size_t len;
        apr_pool_t *ptemp;
        apr_status_t rv;

        //Read javascript source
        apr_pool_create(&ptemp, r->pool);
        if (v8_read_file(r->filename, &src, &len,
                         r->pool, ptemp) == APR_SUCCESS) {
            v8::TryCatch try_catch;
            v8::Handle<v8::String> source = v8::String::New(src, len);

            //Compile the source code.
            v8::Handle<v8::Script> script = v8::Script::Compile(source);

            //Run the script to get the result.
            v8::Handle<v8::Value> result = script->Run();
            if (result.IsEmpty()) {
                v8::String::Utf8Value error(try_catch.Exception());
                _RERR(r, "v8: Script(%s) Failed: %s", r->filename, *error);
                retval = HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            _RERR(r, "v8: Failed to read: %s", r->filename);
            retval = HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_pool_clear(ptemp);
    }

    return retval;
}
