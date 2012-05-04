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
                  r, "[DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                     \
                 s, "[DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);
#define _PDEBUG(p, format, args...)                                     \
    ap_log_perror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  p, "[DEBUG] %s(%d) "format, __FILE__, __LINE__, ##args);

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

    _RERR(r, "v8::log: %s", *value);

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

static v8::Handle<v8::Value> v8_set_content_type(const v8::Arguments& args)
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

    if (value.length() > 0) {
        char *ct = apr_psprintf(r->pool, "%s", *value);
        if (ct) {
            ap_set_content_type(r, ct);
        }
    }

    return v8::Undefined();
}

static v8::Handle<v8::Value> v8_dirname(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::HandleScope scope;
    v8::Handle<v8::Value> arg = args[0];
    //v8::Local<v8::Object> self = args.Holder();
    //v8::Local<v8::External> wrap
    //    = v8::Local<v8::External>::Cast(self->GetInternalField(0));
    v8::String::Utf8Value value(arg);

    if (value.length() == 0) {
        return v8::Undefined();
    }

    char *s = *value + value.length() - 1;

    while (s && *s == '/') {
        *s = '\0';
        s = *value + strlen(*value) - 1;
    }

    s = strrchr(*value, '/');
    if (s != NULL) {
        if (s == *value) {
            return v8::String::New("/");
        }
        *s = '\0';
    }

    return v8::String::New(*value);
}

static v8::Handle<v8::Value> v8_require(const v8::Arguments& args)
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

    apr_status_t rv;
    apr_file_t *fp;
    apr_finfo_t fi;
    apr_size_t bytes;
    void *src;

    rv = apr_file_open(&fp, *value,
                       APR_READ | APR_BINARY | APR_XTHREAD, APR_OS_DEFAULT,
                       r->pool);
    if (rv != APR_SUCCESS) {
        _RERR(r, "v8: file open: %s", *value);
        return v8::Undefined();
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS || fi.size <= 0) {
        _RERR(r, "v8: file info: %s", *value);
        apr_file_close(fp);
        return v8::Undefined();
    }

    src = apr_palloc(r->pool, fi.size);
    if (!src) {
        _RERR(r, "v8: apr_palloc");
        apr_file_close(fp);
        return v8::Undefined();
    }

    rv = apr_file_read_full(fp, src, fi.size, &bytes);
    if (rv != APR_SUCCESS || bytes != fi.size) {
        _RERR(r, "v8: file read: %s", *value);
        apr_file_close(fp);
        return v8::Undefined();
    }

    apr_file_close(fp);

    v8::Handle<v8::String> source = v8::String::New((char *)src, fi.size);
    v8::TryCatch try_catch;

    v8::Handle<v8::Script> script = v8::Script::Compile(source);

    return script->Run();
}

static v8::Handle<v8::Value> v8_header(const v8::Arguments& args)
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

    const char *header = apr_table_get(r->headers_in, *value);

    if (header) {
        return v8::String::New(header);
    } else {
        return v8::Undefined();
    }
}

static v8::Handle<v8::Value> v8_params(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::HandleScope scope;
    v8::Handle<v8::Value> arg = args[0];
    v8::Local<v8::Object> self = args.Holder();
    v8::Local<v8::External> wrap
        = v8::Local<v8::External>::Cast(self->GetInternalField(1));
    v8::String::Utf8Value value(arg);

    apr_table_t *tbl = static_cast<apr_table_t*>(wrap->Value());
    if (!tbl) {
        return v8::Undefined();
    }

    const char *param = apr_table_get(tbl, *value);

    if (param) {
        return v8::String::New(param);
    } else {
        return v8::Undefined();
    }
}

static v8::Handle<v8::Value> v8_json(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::HandleScope scope;
    v8::Handle<v8::Value> arg = args[0];
    //v8::Local<v8::Object> self = args.Holder();
    //v8::Local<v8::External> wrap
    //    = v8::Local<v8::External>::Cast(self->GetInternalField(1));

    v8::Local<v8::Context> context = v8::Context::GetCurrent();
    v8::Local<v8::Object> global = context->Global();
    v8::Local<v8::Object> json =
        global->Get(v8::String::New("JSON"))->ToObject();
    v8::Local<v8::Function> json_stringify =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("stringify")));

    return scope.Close(json_stringify->Call(json, 1, &arg));
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
            //Request parameters.
            apreq_handle_t *apreq = apreq_handle_apache2(r);
            apr_table_t *params = apreq_params(apreq, r->pool);

            //Create a stack-allocated handle scope.
            v8::HandleScope scope;

            //Create function.
            v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();

            global->SetInternalFieldCount(2);
            global->Set(v8::String::New("log"),
                        v8::FunctionTemplate::New(v8_log));
            global->Set(v8::String::New("rputs"),
                        v8::FunctionTemplate::New(v8_rputs));
            global->Set(v8::String::New("content_type"),
                        v8::FunctionTemplate::New(v8_set_content_type));
            global->Set(v8::String::New("dirname"),
                        v8::FunctionTemplate::New(v8_dirname));
            global->Set(v8::String::New("require"),
                        v8::FunctionTemplate::New(v8_require));
            global->Set(v8::String::New("toJson"),
                        v8::FunctionTemplate::New(v8_json));

            //Request Objects.
            v8::Handle<v8::ObjectTemplate> robj = v8::ObjectTemplate::New();
            robj->Set(v8::String::New("method"),
                      v8::String::New(r->method));
            robj->Set(v8::String::New("uri"),
                      v8::String::New(r->uri));
            robj->Set(v8::String::New("filename"),
                      v8::String::New(r->filename));
            global->Set ("request", robj);

            //Header function.
            global->Set("header", v8::FunctionTemplate::New(v8_header));

            //Parameter function.
            global->Set("params", v8::FunctionTemplate::New(v8_params));

            //Create a new context.
            v8::Persistent<v8::Context> context = v8::Context::New();

            //Enter the created context for compiling and
            //running the hello world script.&nbsp;
            v8::Context::Scope context_scope(context);

            v8::Handle<v8::Object> obj = global->NewInstance();
            obj->SetInternalField(0, v8::External::New(r));
            obj->SetInternalField(1, v8::External::New(params));
            context->Global()->Set(v8::String::New("ap"), obj);

            //Create a string containing the JavaScript source code.
            const char *src;
            apr_size_t len;
            apr_pool_t *ptemp;
            apr_status_t rv;

            //Read javascript source
            apr_pool_create(&ptemp, r->pool);
            if (v8_read_file(r->filename, &src, &len,
                             r->pool, ptemp) == APR_SUCCESS) {
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
            apr_pool_clear(ptemp);

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
