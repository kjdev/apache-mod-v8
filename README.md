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

    //request header: ap.header(#val#)
    ap.rputs("Header: Host = " + ap.header("Host") + "\n");
    ap.rputs("Header: User-Agent = " + ap.header("User-Agent") + "\n");

    //request params: ap.params(#val#)
    ap.rputs("Params: test = " + ap.params("test") + "\n");
