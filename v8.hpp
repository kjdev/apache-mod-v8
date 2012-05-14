#ifndef V8_JS_HPP
#define V8_JS_HPP

/* v8 */
#include "v8.h"

/* std */
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#ifdef __cplusplus
}
#endif

/* log */
#ifdef AP_V8_DEBUG_LOG_LEVEL
#define V8_DEBUG_LOG_LEVEL AP_V8_DEBUG_LOG_LEVEL
#else
#define V8_DEBUG_LOG_LEVEL APLOG_DEBUG
#endif

#define _RERR(r, format, args...)                                       \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  r, "[V8] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _SERR(s, format, args...)                                       \
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0,                             \
                 s, "[V8] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _PERR(p, format, args...)                                       \
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  p, "[V8] %s(%d): "format, __FILE__, __LINE__, ##args)

#define _RDEBUG(r, format, args...)                                     \
    ap_log_rerror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  r, "[V8_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                     \
                 s, "[V8_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _PDEBUG(p, format, args...)                                     \
    ap_log_perror(APLOG_MARK, V8_DEBUG_LOG_LEVEL, 0,                    \
                  p, "[V8_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)

/* json function */
#define V8_JSON_OBJECT()                                        \
    v8::Local<v8::Context> context = v8::Context::GetCurrent(); \
    v8::Local<v8::Object> global = context->Global();           \
    v8::Local<v8::Object> json =                                \
        global->Get(v8::String::New("JSON"))->ToObject()

static v8::Handle<v8::Value> v8_objectTojson(v8::Handle<v8::Value> obj)
{
    V8_JSON_OBJECT();

    v8::Local<v8::Function> json_stringify =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("stringify")));

    return json_stringify->Call(json, 1, &obj);
}

static v8::Handle<v8::Value> v8_jsonToobject(v8::Handle<v8::Value> str)
{
    V8_JSON_OBJECT();

    v8::Local<v8::Function> json_parse =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("parse")));

    return json_parse->Call(json, 1, &str);
}

/* callback function */
#define V8_AP_WRAP(num)                                             \
    v8::HandleScope scope;                                          \
    v8::Local<v8::Object> self = args.Holder();                     \
    v8::Local<v8::External> wrap =                                  \
        v8::Local<v8::External>::Cast(self->GetInternalField(num))

#define V8_AP_REQUEST()                                         \
    request_rec *r = static_cast<request_rec*>(wrap->Value())

static v8::Handle<v8::Value> v8_log(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "%s", *value);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_rputs(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    ap_rputs(*value, r);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_content_type(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    if (value.length() > 0) {
        char *ct = apr_psprintf(r->pool, "%s", *value);
        if (ct) {
            ap_set_content_type(r, ct);
        }
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_dirname(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::String::Utf8Value value(args[0]->ToString());

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

static v8::Handle<v8::Value> v8_include(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    apr_status_t rv;
    apr_file_t *fp;
    apr_finfo_t fi;
    apr_size_t bytes;
    void *src;

    rv = apr_file_open(&fp, *value,
                       APR_READ | APR_BINARY | APR_XTHREAD, APR_OS_DEFAULT,
                       r->pool);
    if (rv != APR_SUCCESS) {
        _RERR(r, "file open: %s", *value);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS || fi.size <= 0) {
        _RERR(r, "file info: %s", *value);
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    src = apr_palloc(r->pool, fi.size);
    if (!src) {
        _RERR(r, "apr_palloc");
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_read_full(fp, src, fi.size, &bytes);
    if (rv != APR_SUCCESS || bytes != fi.size) {
        _RERR(r, "file read: %s", *value);
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    apr_file_close(fp);

    v8::TryCatch try_catch;
    v8::Handle<v8::String> source = v8::String::New((char *)src, fi.size);
    v8::Handle<v8::Script> script = v8::Script::Compile(source);
    v8::Handle<v8::Value> result = script->Run();

    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        _RERR(r, "require(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_request(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    const char *val;

    if (strcmp(*value, "method") == 0) {
        val = r->method;
    } else if (strcmp(*value, "uri") == 0) {
        val = r->uri;
    } else if (strcmp(*value, "filename") == 0) {
        val = r->filename;
    } else if (strcmp(*value, "remote_ip") == 0) {
        val = r->connection->remote_ip;
    } else {
        val = NULL;
    }

    if (val) {
        return scope.Close(v8::String::New(val));
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_header(const v8::Arguments& args)
{
    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    if (args.Length() >= 1) {
        v8::String::Utf8Value value(args[0]->ToString());

        const char *header = apr_table_get(r->headers_in, *value);

        if (header) {
            return scope.Close(v8::String::New(header));
        }
    } else {
        v8::Handle<v8::Array> arr(v8::Array::New());

        const apr_array_header_t *header = apr_table_elts(r->headers_in);
        apr_table_entry_t *elts = (apr_table_entry_t *)header->elts;

        for (int i = 0; i < header->nelts; i++) {
            arr->Set(i, v8::String::New(elts[i].key));
        }

        return scope.Close(arr);
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_params(const v8::Arguments& args)
{
    V8_AP_WRAP(1);

    v8::String::Utf8Value value(args[0]->ToString());

    apr_table_t *tbl = static_cast<apr_table_t*>(wrap->Value());
    if (!tbl) {
        return v8::Undefined();
    }

    if (args.Length() >= 1) {
        const char *param = apr_table_get(tbl, *value);

        if (param) {
            return scope.Close(v8::String::New(param));
        }
    } else {
        v8::Handle<v8::Array> arr(v8::Array::New());

        const apr_array_header_t *arr_tbl = apr_table_elts(tbl);
        apr_table_entry_t *elts = (apr_table_entry_t *)arr_tbl->elts;

        for (int i = 0; i < arr_tbl->nelts; i++) {
            arr->Set(i, v8::String::New(elts[i].key));
        }

        return scope.Close(arr);
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_toJson(const v8::Arguments& args)
{
    if (args.Length() < 1 || !args[0]->IsObject()) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Handle<v8::Value> result = v8_objectTojson(arg);

    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_AP_REQUEST();
        _RERR(r, "toJson(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_fromJson(const v8::Arguments& args)
{
    if (args.Length() < 1 || !args[0]->IsString()) {
        return v8::Undefined();
    }

    V8_AP_WRAP(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Handle<v8::Value> result = v8_jsonToobject(arg);
    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_AP_REQUEST();
        _RERR(r, "fromJson(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_response_header(const v8::Arguments& args)
{
    V8_AP_WRAP(0);
    V8_AP_REQUEST();

    if (args.Length() < 2) {
        return scope.Close(v8::Undefined());
    }

    v8::String::Utf8Value key(args[0]->ToString());
    v8::String::Utf8Value value(args[1]->ToString());

    apr_table_set(r->headers_out, *key, *value);

    return scope.Close(v8::Boolean::New(true));
}

static v8::Handle<v8::Value> v8_response_code(const v8::Arguments& args)
{
    V8_AP_WRAP(2);

    if (args.Length() >= 1 && args[0]->IsNumber()) {
        int *code = (int *)(wrap->Value());
        *code = args[0]->ToInt32()->Int32Value();
        return scope.Close(v8::Boolean::New(true));
    }

    return scope.Close(v8::Undefined());
}

/* V8::js class */
namespace V8 {
class js
{
public:
    js() {
        if (!v8::Context::InContext()) {
            context_enter_ = true;
            global_context_ = v8::Context::New();
            global_context_->Enter();
            context_ = v8::Local<v8::Context>::New(global_context_);
        } else {
            context_enter_ = false;
            context_ = v8::Context::GetCurrent();
        }

        v8::Context::Scope scope(context_);

        //ap(apache) object template.
        v8::Handle<v8::ObjectTemplate> ap_tmpl = v8::ObjectTemplate::New();
        ap_tmpl->SetInternalFieldCount(3);
        ap_tmpl->Set(v8::String::New("log"),
                     v8::FunctionTemplate::New(v8_log));
        ap_tmpl->Set(v8::String::New("dirname"),
                     v8::FunctionTemplate::New(v8_dirname));
        ap_tmpl->Set(v8::String::New("include"),
                     v8::FunctionTemplate::New(v8_include));
        ap_tmpl->Set(v8::String::New("toJson"),
                     v8::FunctionTemplate::New(v8_toJson));
        ap_tmpl->Set(v8::String::New("fromJson"),
                     v8::FunctionTemplate::New(v8_fromJson));

        //Request function.
        ap_tmpl->Set(v8::String::New("request"),
                     v8::FunctionTemplate::New(v8_request));

        //Header function.
        ap_tmpl->Set(v8::String::New("header"),
                     v8::FunctionTemplate::New(v8_header));

        //Parameter function.
        ap_tmpl->Set(v8::String::New("params"),
                     v8::FunctionTemplate::New(v8_params));

        //Response function.
        ap_tmpl->Set(v8::String::New("content_type"),
                     v8::FunctionTemplate::New(v8_content_type));
        ap_tmpl->Set(v8::String::New("rputs"),
                     v8::FunctionTemplate::New(v8_rputs));
        ap_tmpl->Set(v8::String::New("rheader"),
                     v8::FunctionTemplate::New(v8_response_header));
        ap_tmpl->Set(v8::String::New("rcode"),
                     v8::FunctionTemplate::New(v8_response_code));

        //object instance.
        ap_ = ap_tmpl->NewInstance();
        context_->Global()->Set(v8::String::New("ap"), ap_);
    }

    ~js() {
        if (context_enter_) {
            global_context_->DetachGlobal();
            global_context_->Exit();
            global_context_.Dispose();
        }
    }

    bool run(const char *src, apr_size_t len,
             request_rec *r, apr_table_t *params, int *code) {
        v8::TryCatch try_catch;

        ap_->SetInternalField(0, v8::External::New(r));
        ap_->SetInternalField(1, v8::External::New(params));
        ap_->SetInternalField(2, v8::External::New(code));

        v8::Handle<v8::String> source = v8::String::New(src, len);

        //Compile the source code.
        v8::Handle<v8::Script> script = v8::Script::Compile(source);
        if (script.IsEmpty()) {
            v8::String::Utf8Value error(try_catch.Exception());
            _RERR(r, "Script(%s) Failed: %s", r->filename, *error);
            return false;
        }

        //Run the script to get the result.
        v8::Handle<v8::Value> result = script->Run();
        if (result.IsEmpty()) {
            v8::String::Utf8Value error(try_catch.Exception());
            _RERR(r, "Script(%s) Failed: %s", r->filename, *error);
            return false;
        }

        return true;
    }

private:
    bool context_enter_;

    v8::HandleScope scope_;
    v8::Persistent<v8::Context> global_context_;

    v8::Handle<v8::Object> ap_;
    v8::Local<v8::Context> context_;
};
}

#endif // V8_JS_HPP
