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
//#include "http_main.h"
#include "http_log.h"
//#include "util_script.h"
#include "ap_config.h"
#include "apr_strings.h"
#ifdef __cplusplus
}
#endif

#define _V8_RERR(r, format, args...)                                    \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  r, "[V8] %s(%d) "format, __FILE__, __LINE__, ##args);

/* json function */
#define V8_JSON_OBJECT                                         \
    v8::Local<v8::Context> context = v8::Context::GetCurrent(); \
    v8::Local<v8::Object> global = context->Global();           \
    v8::Local<v8::Object> json =                                \
        global->Get(v8::String::New("JSON"))->ToObject()

static v8::Handle<v8::Value> v8_objectTojson(v8::Handle<v8::Value> obj)
{
    V8_JSON_OBJECT;

    v8::Local<v8::Function> json_stringify =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("stringify")));

    return json_stringify->Call(json, 1, &obj);
}

static v8::Handle<v8::Value> v8_jsonToobject(v8::Handle<v8::Value> str)
{
    V8_JSON_OBJECT;

    v8::Local<v8::Function> json_parse =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("parse")));

    return json_parse->Call(json, 1, &str);
}

/* callback function */
#define V8_CALLBACK_PARAMS(internal)                                    \
    v8::HandleScope scope;                                              \
    v8::Local<v8::Object> self = args.Holder();                         \
    v8::Local<v8::External> wrap =                                      \
        v8::Local<v8::External>::Cast(self->GetInternalField(internal))
#define V8_CALLBACK_AP_REC                                      \
    request_rec *r = static_cast<request_rec*>(wrap->Value())

static v8::Handle<v8::Value> v8_log(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

    v8::String::Utf8Value value(args[0]->ToString());

    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "v8::log: %s", *value);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_rputs(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

    v8::String::Utf8Value value(args[0]->ToString());

    ap_rputs(*value, r);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_set_content_type(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

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

static v8::Handle<v8::Value> v8_require(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

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
        _V8_RERR(r, "file open: %s", *value);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS || fi.size <= 0) {
        _V8_RERR(r, "file info: %s", *value);
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    src = apr_palloc(r->pool, fi.size);
    if (!src) {
        _V8_RERR(r, "apr_palloc");
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_read_full(fp, src, fi.size, &bytes);
    if (rv != APR_SUCCESS || bytes != fi.size) {
        _V8_RERR(r, "file read: %s", *value);
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
        _V8_RERR(r, "require(%s) Failed: %s", r->filename, *error);
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

    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

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
    V8_CALLBACK_PARAMS(0);
    V8_CALLBACK_AP_REC;

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
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_CALLBACK_PARAMS(1);

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

    V8_CALLBACK_PARAMS(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Handle<v8::Value> result = v8_objectTojson(arg);

    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_CALLBACK_AP_REC;
        _V8_RERR(r, "toJson(%s) Failed: %s", r->filename, *error);
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

    V8_CALLBACK_PARAMS(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Handle<v8::Value> result = v8_jsonToobject(arg);
    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_CALLBACK_AP_REC;
        _V8_RERR(r, "fromJson(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

/* V8::js class */
namespace V8 {
class js
{
public:
    v8::Handle<v8::Object> ap;

    js() {
        global_ = v8::ObjectTemplate::New();
        context_ = v8::Context::New(NULL, global_);
        context_->Enter();

        //ap(apache) object template.
        v8::Handle<v8::ObjectTemplate> ap_tmpl = v8::ObjectTemplate::New();
        ap_tmpl->SetInternalFieldCount(2);
        ap_tmpl->Set(v8::String::New("log"),
                     v8::FunctionTemplate::New(v8_log));
        ap_tmpl->Set(v8::String::New("rputs"),
                     v8::FunctionTemplate::New(v8_rputs));
        ap_tmpl->Set(v8::String::New("content_type"),
                     v8::FunctionTemplate::New(v8_set_content_type));
        ap_tmpl->Set(v8::String::New("dirname"),
                     v8::FunctionTemplate::New(v8_dirname));
        ap_tmpl->Set(v8::String::New("require"),
                     v8::FunctionTemplate::New(v8_require));
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

        //object instance.
        ap = ap_tmpl->NewInstance();
        context_->Global()->Set(v8::String::New("ap"), ap);
    }

    ~js() {
        context_->DetachGlobal();
        context_->Exit();
        context_.Dispose();
    }

private:
    v8::HandleScope scope_;
    v8::Handle<v8::ObjectTemplate> global_;
    v8::Persistent<v8::Context> context_;
};
}

#endif // V8_JS_HPP
