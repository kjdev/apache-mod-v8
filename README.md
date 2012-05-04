# mod_v8 #

mod_v8 is Javascript V8 Engine handler module for Apache HTTPD Server.

## Dependencies ##

* [V8](http://code.google.com/p/v8)
* [libapreq2](http://httpd.apache.org/apreq)

## Build ##

    % ./autogen.sh (or autoreconf -i)
    % ./configure [OPTION]
    % make
    % make install

### Build Options ###

V8 path.

* --with-v8=PATH  [default=/usr/include]
* --with-v8-lib=PATH  [default=no]

V8 isolate.

* --enable-v8-isolate  [default=no]

apache path.

* --with-apxs=PATH  [default=yes]
* --with-apr=PATH  [default=yes]
* --with-apreq2=PATH  [default=yes]

## Configration ##

httpd.conf:

    LoadModule v8_module modules/mod_v8.so
    AddHandler v8-script .v8

## Example ##

test.v8:

    //apache log (critical error log): ap.log(#val#)
    ap.log("hello");

    //output: ap.rputs(#val#)
    ap.rputs("Hello, World" + "\n");

    //request parameter (method/uri/filename): ap.request.#val#
    ap.rputs("Method = " + ap.request.method + "\n");
    ap.rputs("Uri = " + ap.request.uri + "\n");
    ap.rputs("Filename = " + ap.request.filename + "\n");
    ap.rputs("Remote IP = " + ap.request.remote_ip + "\n");

    //request header: ap.header(#val#)
    ap.rputs("Header: Host = " + ap.header("Host") + "\n");
    ap.rputs("Header: User-Agent = " + ap.header("User-Agent") + "\n");

    //request header keys: ap.header()
    var headers = ap.header();
    for (var i = 0; i < headers.length; i ++) {
        ap.rputs(headers[i] + " => " + ap.header(headers[i]) + "\n");
    }

    //request params: ap.params(#val#)
    ap.rputs("Params: test = " + ap.params("test") + "\n");

    //dirname: ap.dirname(#val#)
    ap.rputs(ap.dirname(ap.request.filename) + "\n");

    //require: ap.require(#val#)
    ap.require(ap.dirname(ap.request.filename) + "/sub.v8");

    //content-type: ap.content_type(#val#)
    //default: text/plain; charset=UTF-8
    ap.content_type("text/html; charset=UTF-8");

    //json: ap.toJson(#val#)
    var obj = { test: "TEST", hoge:"HOGE" };
    ap.rputs(ap.toJson(obj) + "\n");
