/*
**  mod_v8.cpp -- Apache mongo module
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

/* v8 */
#include "v8.h"

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

//#include "apreq2/apreq_module_apache2.h"
#ifdef __cplusplus
}
#endif

//#define V8_CONTENT_TYPE "application/json; charset=utf-8";
//#define V8_CONTENT_TYPE "application/x-javascript; charset=utf-8";
#define V8_CONTENT_TYPE "text/html; charset=UTF-8";

#define V8_DEBUG_LOG_LEVEL APLOG_CRIT
//#define V8_DEBUG_LOG_LEVEL APLOG_DEBUG

#define _RERR(r, format, args...)                                   \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                        \
                  r, "%s(%d) "format, __FILE__, __LINE__, ##args);
#define _SERR(s, format, args...)                                  \
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0,                        \
                 s, "%s(%d) "format, __FILE__, __LINE__, ##args);
#define _RDEBUG(r, format, args...)                                     \
    ap_log_rerror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  r, "[DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                     \
                 s, "[DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);

/* Functions */
static int v8_handler(request_rec* r);

/* Commands */
static const command_rec v8_cmds[] =
{
    { NULL, NULL, NULL, 0, TAKE1, NULL }
};

static void v8_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(v8_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

#ifdef __cplusplus
extern "C" {
#endif
module AP_MODULE_DECLARE_DATA v8_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    NULL,                       /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    v8_cmds,                    /* table of config file commands       */
    v8_register_hooks           /* register hooks                      */
};
#ifdef __cplusplus
}
#endif

static apr_status_t v8_read_file(const char *path,
                                 const char **out,
                                 apr_size_t *outlen,
                                 apr_pool_t *p,
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
        return rv;
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(ptemp);
    apr_bucket_brigade *bb = apr_brigade_create(ptemp, ba);

    apr_brigade_insert_file(bb, fp, 0, fi.size, ptemp);

    rv = apr_brigade_pflatten(bb, &c, &len, p);
    if (rv) {
        return rv;
    }

    *out = c;
    *outlen = len;

    return APR_SUCCESS;
}

/* V8 callback function */
static v8::Handle<v8::Value> v8_log(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::HandleScope scope;
    v8::Handle<v8::Value> arg = args[0];
    v8::Local<v8::Object> self = args.Holder();
    v8::Local<v8::External> wrap =
        v8::Local<v8::External>::Cast(self->GetInternalField(0));
    v8::String::Utf8Value value(arg);

    request_rec *r = static_cast<request_rec*>(wrap->Value());

    _RERR( r, "v8::log: %s", *value);

    return v8::Undefined();
}

static v8::Handle<v8::Value> v8_rputs(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::HandleScope scope;
    v8::Handle<v8::Value> arg = args[0];
    v8::Local<v8::Object> self = args.Holder();
    v8::Local<v8::External> wrap
        = v8::Local<v8::External>::Cast(self->GetInternalField(0));
    v8::String::Utf8Value value(arg);

    request_rec *r = static_cast<request_rec*>(wrap->Value());

    ap_rputs(*value, r);

    return v8::Undefined();
}

/* content handler */
static int v8_handler(request_rec *r)
{
    int retval = OK;

    if (strcmp(r->handler, "v8-script")) {
        return DECLINED;
    }

    /* content type */
    r->content_type = V8_CONTENT_TYPE;

    if (!r->header_only) {
#ifdef AP_USE_V8_ISOLATE
        v8::Isolate *isolate = v8::Isolate::New();
        isolate->Enter();
        isolate = v8::Isolate::GetCurrent();
        _RDEBUG(r, "v8 isolate: enabled");
#endif
        {
            //Create a stack-allocated handle scope.
            v8::HandleScope scope;

            //Create function
            v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();

            //Create function.
            global->SetInternalFieldCount(1);
            global->Set(v8::String::New("log"),
                        v8::FunctionTemplate::New(v8_log));
            global->Set(v8::String::New("rputs"),
                        v8::FunctionTemplate::New(v8_rputs));

            //Create a new context.
            v8::Persistent<v8::Context> context = v8::Context::New();

            //Enter the created context for compiling and
            //running the hello world script.&nbsp;
            v8::Context::Scope context_scope(context);

            v8::Handle<v8::Object> obj = global->NewInstance();
            obj->SetInternalField(0, v8::External::New(r));
            context->Global()->Set(v8::String::New("ap"), obj);

            //Create a string containing the JavaScript source code.
            const char *src;
            apr_size_t len;
            apr_pool_t *tpool;
            apr_status_t rv;

            //Read javascript source
            apr_pool_create(&tpool, r->pool);
            if (v8_read_file(r->filename, &src, &len,
                             r->pool, tpool) == APR_SUCCESS) {
                v8::Handle<v8::String> source = v8::String::New(src, len);
                v8::TryCatch try_catch;

                //Compile the source code.
                v8::Handle<v8::Script> script = v8::Script::Compile(source);
                //Run the script to get the result.
                v8::Handle<v8::Value> result = script->Run();

                if (result.IsEmpty()) {
                    v8::String::AsciiValue error(try_catch.Exception());
                    _RERR(r, "v8: Script(%s) Failed: %s", r->filename, *error);
                    retval = HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                _RERR(r, "v8: Failed to read: %s", r->filename);
                retval = HTTP_INTERNAL_SERVER_ERROR;
            }
            apr_pool_clear(tpool);

            //Dispose the persistent context.
            context.Dispose();
        }

#ifdef AP_USE_V8_ISOLATE
        isolate->Exit();
        isolate->Dispose();
#endif
    }

    return retval;
}
