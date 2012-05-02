# mod_v8 #

mod_v8 is Javascript V8 Engine handler module for Apache HTTPD Server.

## Dependencies ##

* [V8](http://code.google.com/p/v8)

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
* --with-apu=PATH  [default=no]

## Configration ##

httpd.conf:

    LoadModule v8_module modules/mod_v8.so
    AddHandler v8-script .v8
