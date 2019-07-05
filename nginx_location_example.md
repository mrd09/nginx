[nginx location](http://nginx.org/en/docs/http/ngx_http_core_module.html#location)
[Other example](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
[proxy_pass](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)
[http code](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.2)
[proxy_pass example](https://www.liaohuqiu.net/posts/nginx-proxy-pass/)

# Overview Example of nginx:
##  Example nginx config:
- `proxy_params` config: `add parameter to IP HEADER` `when proxy to backend server`

```
$ cat /etc/nginx/proxy_params
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

- nginx config "/etc/nginx/conf.d/test.com.conf" for site "test.com"
```
server {
    listen              1.1.1.1:443 ssl http2;
    listen              4443 ssl http2 default_server;
    server_name         test.com;
    ssl_certificate     fullchain.pem;
    ssl_certificate_key privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location /abc/ {
        proxy_pass http://1.1.1.1:1234/abc/;
        include /etc/nginx/proxy_params;
    }


server {
    listen      1.1.1.1:80;
    server_name test.com;
    return      301 https://$host$request_uri;
}
```
    
##  Detail explain:
###     1. user access test.com/abc -> 301 -> test.com/abc/ (append slash) [location properties]
####        1.1. match first config: test.com/abc
- config matched:
```
server {
    listen      1.1.1.1:80;
    server_name test.com;

->  return      301 https://$host$request_uri;
    ->  $host: host name from the request line, or host name from the “Host” request header field, or the server name matching a request 
        ->  test.com
    ->  $request_uri: full original request URI (with arguments)
        ->  /abc/
    ->  return      301 https://test.com/abc;
```

- Test request:
```
$ curl  -vv -H -L test.com/abc  => add request host name to HTTP HEADER
*   Trying 123.45.123.45...
* Connected to wallet.stg.truemoney.com.vn (123.45.123.45) port 80 (#0)
> GET /portal HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Date: Wed, 03 Jul 2019 08:11:45 GMT
< Content-Type: text/html
< Content-Length: 178
< Connection: keep-alive
< Location: https://test.com/abc    => client redirect request to https://test.com/abc
```

####        1.2. match second config: https://test.com/abc
- config matched:
```
server {
    listen              1.1.1.1:443 ssl http2;
    listen              4443 ssl http2 default_server;
    server_name         test.com;
    ssl_certificate     fullchain.pem;
    ssl_certificate_key privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location /abc/ {
        proxy_pass http://1.1.1.1:1234/abc/;
        include /etc/nginx/proxy_params;
    }
```

- ssl establish:
```
* Ignoring the response-body
* Connection #0 to host test.com left intact
* Issue another request to this URL: 'https://test.com/abc'
* Found bundle for host test.com: 0x5652282022f0 [can pipeline]
*   Trying 123.45.123.45...
* Connected to test.com (123.45.123.45) port 443 (#1)
* found 148 certificates in /etc/ssl/certs/ca-certificates.crt
* found 592 certificates in /etc/ssl/certs
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_256_GCM_SHA384
*    server certificate verification OK
*    server certificate status verification SKIPPED
*    common name: *. (matched)
*    server certificate expiration date OK
*    server certificate activation date OK
*    certificate public key: RSA
*    certificate version: #3
*    subject: CN=*.
*    start date: Sat, 08 Jun 2019 01:47:29 GMT
*    expire date: Fri, 06 Sep 2019 01:47:29 GMT
*    issuer: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
*    compression: NULL
* ALPN, server accepted to use http/1.1
```

- location redirect append slash(/) at the end of uri:
```
> GET /abc HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Content-Type: text/html
< Content-Length: 178
< Location: https://test.com/abc/
< Connection: keep-alive
< Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
< 
* Ignoring the response-body
* Connection #1 to host test.com left intact
* Issue another request to this URL: 'https://test.com/abc/'
* Found bundle for host test.com: 0x5652282022f0 [can pipeline]
* Re-using existing connection! (#1) with host test.com
* Connected to test.com (52.77.191.3) port 443 (#1)
```

###     2. Proxypass to backend server:
- proxy pass config:
```
    location /abc/ {
        proxy_pass http://1.1.1.1:1234/abc/;
        include /etc/nginx/proxy_params;
    }
```

- Result from backend server response to nginx server:
```
> GET /portal/ HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 
< Server: nginx
< Date: Wed, 03 Jul 2019 08:11:46 GMT
< Content-Length: 0
< Connection: keep-alive
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Methods: POST, GET, PUT, OPTIONS, DELETE
< Access-Control-Max-Age: 3600
< Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Key, Authorization
< X-Application-Context: application:8007
< Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
< 
* Connection #1 to host test.com left intact
```

- A `request URI is passed to the server` as follows:
    - If the `proxy_pass directive` is `specified with a URI (Ex:proxy_pass http://127.0.0.1/remote/)`, then:
        - when a `request is passed to the server`, :
            + the `part of a normalized request URI matching the location` is `replaced by a URI` `specified in the directive`
            + And `append the rest after the matched` to proxypass: 
```
location /app/ {
    proxy_pass      http://192.168.154.102/maped_dir/;   =>>> Notice about the slash at the end of the proxy_pass
}

location /name/ {
    proxy_pass http://127.0.0.1/remote/;    =>>> Notice about the slash at the end of the proxy_pass
}

User access test.com/app -> 301 redirect ->  test.com/app/ -> proxy_pass http://192.168.154.102/maped_dir/
User access test.com/app/xxxxx 
    -> match /app/
    -> replace to: http://192.168.154.102/maped_dir/
    -> append the rest after matched "/app/": "xxxxx" to: proxy_pass http://192.168.154.102/maped_dir/xxxxx
```

    - If proxy_pass is `specified without a URI`, the `request URI is passed to the server in the same form as sent by a client`:
            - when `the original request` is processed, or `the full normalized request URI`:
                + `is passed when processing the changed URI`:
```
        location /app/ {
            proxy_pass      http://192.168.154.102:8080;     =>>> Notice about there is no trailing slash (/)  at the end of the proxy_pass
        }

        location /portal/ {
            proxy_pass http://127.0.0.1:8080/portal;     =>>> Notice about there is no trailing slash (/)  at the end of the proxy_pass
        }

User access test.com/app -> 301 redirect ->  test.com/app/ -> proxy_pass http://192.168.154.102:8080/app
User access test.com/app/xxxxx -> proxypass whole string to: proxy_pass http://192.168.154.102:8080/app/xxxxx

User access test.com/portal/abc -> proxypass whole string to: proxy_pass http://127.0.0.1:8080/portal/portal/abc =>> error case
If we append slash(/) in config:
        location /portal/ {
            proxy_pass http://127.0.0.1:8080/portal/;
        }

    => User access right to the case proxy_pass is `specified with a URI`: test.com/portal/abc
        -> match /portal/
        -> replace to: http://192.168.154.102/portal/
        -> append the rest after matched "/portal/": "abc" to: proxy_pass http://192.168.154.102/portal/abc
```

# What is URL: The general form of an URL has four parts

- Part1: A scheme followed by a colon.
    + Invokes a TCP/IP-based application level protocol
    + Schemes are: http, https, ftp, news, mailto, file, telnet. 

- Part2: A server name.
    + A // followed by the host name or IP address of the server
    + Not needed if the server is the default
            news server
            mail server 

- Part3: An optional port number. Standard or default port numbers are:
    + ftp     *
    + ssh     22
    + telnet  23
    + smtp    25
    + gopher  70
    + http    80
    + nntp    119
    + SSL     443

- Part4: A path.
    + Consisting of folders and/or files.
    + May include a file extension which identifies the type of document.
    + May also include a QUERY_STRING with arguments. 
    * Ftp uses port 20 for data and port 21 for flow control.

# URL vs URN vs URI:
-  What is an URL
    + An Uniform Resource Locator (URL) is the term used to identify an Internet resource, and can be specified in a single line of text.

- What is an URN
    + An Uniform Resource Name (URN) is the term used to identify an Internet resource, without the use of a scheme, and can be specified in a single line of text.

- What is an URI: 
    + `URI = scheme:[//authority]path[?query][#fragment]` 
        + where the authority component divides into three subcomponents: `authority = [userinfo@]host[:port]`

    + An Uniform Resource Identifier (URI) is used by a browser to identify a single document, and it too can be specified in a single line of text.

- Example:
```
URL     http://www.pierobon.org/iis/review1.htm
URN     www.pierobon.org/iis/review1.htm#one
URI     http://www.pierobon.org/iis/review1.htm.html#one
```

- [Other example](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier):
```
          userinfo       host      port
          ┌──┴───┐ ┌──────┴──────┐ ┌┴┐
  https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top
  └─┬─┘   └───────────┬──────────────┘└───────┬───────┘ └───────────┬─────────────┘ └┬┘
  scheme          authority                  path                 query           fragment

  ldap://[2001:db8::7]/c=GB?objectClass?one
  └┬─┘   └─────┬─────┘└─┬─┘ └──────┬──────┘
  scheme   authority   path      query

  mailto:John.Doe@example.com
  └─┬──┘ └────┬─────────────┘
  scheme     path

  news:comp.infosystems.www.servers.unix
  └┬─┘ └─────────────┬─────────────────┘
  scheme            path

  tel:+1-816-555-1212
  └┬┘ └──────┬──────┘
  scheme    path

  telnet://192.0.2.16:80/
  └─┬──┘   └─────┬─────┘│
  scheme     authority  path

  urn:oasis:names:specification:docbook:dtd:xml:4.1.2
  └┬┘ └──────────────────────┬──────────────────────┘
  scheme                    path
```

# HTTP code:
[http code](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.2)

# location module:
- Syntax: 
```
Syntax:     location [ = | ~ | ~* | ^~ ] uri { ... }
location @name { ... }
Default:    —
Context:    server, location

Sets configuration depending on a request URI.
```

- The matching is performed against a normalized URI, after decoding the text encoded in the “%XX” form, resolving references to relative path components “.” and “..”, and possible compression of two or more adjacent slashes into a single slash. 

- A location can either be defined by:
    - a `prefix string`, or by 
    - a `regular expression`.
        - are specified with the `preceding “~*” modifier` (for `case-insensitive matching`)
        - or `the “~” modifier` (for `case-sensitive matching`)

- To find location matching a given request, nginx:
    - `first` : `checks locations defined` using the prefix strings (prefix locations)
        - Among them, the `location with the longest matching prefix` `is selected and remembered`.
    - Then regular expressions are checked in the order of their appearance in the configuration file
        - The search of regular expressions terminates on the first match, and the corresponding configuration is used
        - If no match with a regular expression is found then the configuration of the prefix location remembered earlier is used. 

- If the `longest matching prefix location has the “^~” modifier` then `regular expressions are not checked`. 

- Also, `using the “=” modifier` it is possible to `define an exact match of URI and location`

- Let’s illustrate the above by an example:
```
location = / {
    [ configuration A ]
}

location / {
    [ configuration B ]
}

location /documents/ {
    [ configuration C ]
}

location ^~ /images/ {
    [ configuration D ]
}

location ~* \.(gif|jpg|jpeg)$ {
    [ configuration E ]
}
```

    - The `“/” request` will `match configuration A`, 
    - The `“/index.html”` request will `match configuration B`
    - The `“/documents/document.html”` request will `match configuration C`
    - the `“/images/1.gif”` request will `match configuration D`
    - the `“/documents/1.jpg”` request will `match configuration E`

- The “@” prefix defines a named location. Such a location is not used for a regular request processing, but instead used for request redirection. They cannot be nested, and cannot contain nested locations. 

##  "location" module nginx(URI with and without slash(/) at the end):
- The `location with the longest matching prefix` `is selected and remembered`

- If a `location is defined by a prefix string` that:
    - `ends with the slash(/) character`, and 
    - `requests are processed by` one of [proxy_pass](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass), [fastcgi_pass](http://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass), [uwsgi_pass](http://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_pass), [scgi_pass](http://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_pass), [memcached_pass](http://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_pass), or [grpc_pass](http://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_pass), then the special processing is performed.

- In response to a request with URI equal to this string, but `without the trailing slash`,:
    - a `permanent redirect with the code 301` `will be returned to the requested URI` `with the slash(/) appended`

- `If this is not desired`, an `exact match of the URI(= ) and location could be defined` like this: 

- Example:
```
- nginx config not use the exact match:
location /user/ {
    proxy_pass http://user.example.com;
}

user access abc.com/user -> 301 -> abc.com/user/ (append slash) -> proxy_pass http://user.example.com

- nginx config use the exact match:
location = /user/ {
    proxy_pass http://user.example.com;
}

user access abc.com/user -> will not match the loction /user/ because lack of slash at tail
```

- If a `location is defined by a prefix string` that:
    - `not ends with the slash(/) character`
    - so the behaviour the same as 

###     location without regular expression requests are processed by proxy_pass:
[proxy_pass](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)
[proxy_pass example](https://www.liaohuqiu.net/posts/nginx-proxy-pass/)

- Syntax:
```
Syntax:     proxy_pass URL;
Default:    —
Context:    location, if in location, limit_except
```

- Sets the `protocol and address of a proxied server` and `an optional URI` `to which a location should be mapped`. 
    - `As a protocol, “http” or “https” can be specified`. 
    - `The address` 
        - can be specified `as a domain name or IP address`, and `an optional port`: `proxy_pass http://localhost:8000/uri/;`
        - or as a `UNIX-domain socket path` specified after the word “unix” and enclosed in colons: `proxy_pass http://unix:/tmp/backend.socket:/uri/;`

- `If a domain name resolves to several addresses`, `all of them will be used` `in a round-robin fashion`. 
- In addition, an address can be specified as a server group. 

- A `request URI is passed to the server` as follows:
    - If the `proxy_pass directive` is `specified with a URI (Ex:proxy_pass http://127.0.0.1/remote/)`, then:
        - when a `request is passed to the server`, :
            + the `part of a normalized request URI matching the location` is `replaced by a URI` `specified in the directive`
            + And `append the rest after the matched` to proxypass: 
```
location /app/ {
    proxy_pass      http://192.168.154.102/maped_dir/;   =>>> Notice about the slash at the end of the proxy_pass
}

location /name/ {
    proxy_pass http://127.0.0.1/remote/;    =>>> Notice about the slash at the end of the proxy_pass
}

User access test.com/app -> 301 redirect ->  test.com/app/ -> proxy_pass http://192.168.154.102/maped_dir/
User access test.com/app/xxxxx 
    -> match /app/
    -> replace to: http://192.168.154.102/maped_dir/
    -> append the rest after matched "/app/": "xxxxx" to: proxy_pass http://192.168.154.102/maped_dir/xxxxx
```

    - If proxy_pass is `specified without a URI`, the `request URI is passed to the server in the same form as sent by a client`:
            - when `the original request` is processed, or `the full normalized request URI`:
                + `is passed when processing the changed URI`:
```
        location /app/ {
            proxy_pass      http://192.168.154.102:8080;     =>>> Notice about there is no trailing slash (/)  at the end of the proxy_pass
        }

        location /portal/ {
            proxy_pass http://127.0.0.1:8080/portal;     =>>> Notice about there is no trailing slash (/)  at the end of the proxy_pass
        }

User access test.com/app -> 301 redirect ->  test.com/app/ -> proxy_pass http://192.168.154.102:8080/app
User access test.com/app/xxxxx -> proxypass whole string to: proxy_pass http://192.168.154.102:8080/app/xxxxx

User access test.com/portal/abc -> proxypass whole string to: proxy_pass http://127.0.0.1:8080/portal/portal/abc =>> error case
If we append slash(/) in config:
        location /portal/ {
            proxy_pass http://127.0.0.1:8080/portal/;
        }

    => User access right to the case proxy_pass is `specified with a URI`: test.com/portal/abc
        -> match /portal/
        -> replace to: http://192.168.154.102/portal/
        -> append the rest after matched "/portal/": "abc" to: proxy_pass http://192.168.154.102/portal/abc
```

# return module:
[nginx http rewrite module](http://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return)

- Syntax:
```
Syntax:   return code [text];
return code URL;
return URL;
Default:    —
Context:    server, location, if
```

- Stops processing and returns the specified code to a client. 
    - The non-standard code 444 closes a connection without sending a response header. 
- In addition, a URL for temporary redirect with the code 302 can be specified as the sole parameter. 
    - Such a parameter should start with the “http://”, “https://”, or “$scheme” string. 
    - A URL can contain variables. 

# Reverse proxy config:
##  proxy_set_header:
- Syntax:
```
Syntax:     proxy_set_header field value;
Default:    

proxy_set_header Host $proxy_host;

proxy_set_header Connection close;

Context:    http, server, location
```

- `Allows redefining or appending fields` `to the request header` `passed to the proxied server`.

- The `value can contain text, variables, and their combinations`.
    - These directives are inherited from the previous level if and only if there are no proxy_set_header directives defined on the current level. 
    - By default, only two fields are redefined:
```
        proxy_set_header Host       $proxy_host;
        proxy_set_header Connection close;
```


- Example config:
```
$ cat /etc/nginx/proxy_params
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;


server {
    listen              1.1.1.1:443 ssl http2;
    listen              4443 ssl http2 default_server;
    server_name         test.com;
    ssl_certificate     fullchain.pem;
    ssl_certificate_key privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location /abc/ {
        proxy_pass http://1.1.1.1:1234/abc/;
        include /etc/nginx/proxy_params;
    }


server {
    listen      1.1.1.1:80;
    server_name test.com;
    return      301 https://$host$request_uri;
}
```
    
    - Detail explain:
```
1. user access test.com/abc -> 301 -> test.com/abc/ (append slash) [location properties]

1.1. match 1 in nginx server: test.com/abc
server {
    listen      1.1.1.1:80;
    server_name test.com;

->  return      301 https://$host$request_uri;
    ->  $host: host name from the request line, or host name from the “Host” request header field, or the server name matching a request 
        ->  test.com
    ->  $request_uri: full original request URI (with arguments)
        ->  /abc/
    ->  return      301 https://test.com/abc;

$ curl  -vv -H -L test.com/abc  => add request host name to HTTP HEADER
*   Trying 123.45.123.45...
* Connected to wallet.stg.truemoney.com.vn (123.45.123.45) port 80 (#0)
> GET /portal HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Date: Wed, 03 Jul 2019 08:11:45 GMT
< Content-Type: text/html
< Content-Length: 178
< Connection: keep-alive
< Location: https://test.com/abc    => client redirect request to https://test.com/abc


1.2. match 2: https://test.com/abc
server {
    listen              1.1.1.1:443 ssl http2;
    listen              4443 ssl http2 default_server;
    server_name         test.com;
    ssl_certificate     fullchain.pem;
    ssl_certificate_key privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location /abc/ {
        proxy_pass http://1.1.1.1:1234/abc/;
        include /etc/nginx/proxy_params;
    }

- ssl establish:
* Ignoring the response-body
* Connection #0 to host test.com left intact
* Issue another request to this URL: 'https://test.com/abc'
* Found bundle for host test.com: 0x5652282022f0 [can pipeline]
*   Trying 123.45.123.45...
* Connected to test.com (123.45.123.45) port 443 (#1)
* found 148 certificates in /etc/ssl/certs/ca-certificates.crt
* found 592 certificates in /etc/ssl/certs
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_256_GCM_SHA384
*    server certificate verification OK
*    server certificate status verification SKIPPED
*    common name: *. (matched)
*    server certificate expiration date OK
*    server certificate activation date OK
*    certificate public key: RSA
*    certificate version: #3
*    subject: CN=*.
*    start date: Sat, 08 Jun 2019 01:47:29 GMT
*    expire date: Fri, 06 Sep 2019 01:47:29 GMT
*    issuer: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
*    compression: NULL
* ALPN, server accepted to use http/1.1

- location redirect append slash(/) at the end of uri:
> GET /abc HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Content-Type: text/html
< Content-Length: 178
< Location: https://test.com/abc/
< Connection: keep-alive
< Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
< 
* Ignoring the response-body
* Connection #1 to host test.com left intact
* Issue another request to this URL: 'https://test.com/abc/'
* Found bundle for host test.com: 0x5652282022f0 [can pipeline]
* Re-using existing connection! (#1) with host test.com
* Connected to test.com (52.77.191.3) port 443 (#1)

2. Proxypass to backend server: 
> GET /portal/ HTTP/1.1
> Host: test.com
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 
< Server: nginx
< Date: Wed, 03 Jul 2019 08:11:46 GMT
< Content-Length: 0
< Connection: keep-alive
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Methods: POST, GET, PUT, OPTIONS, DELETE
< Access-Control-Max-Age: 3600
< Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Key, Authorization
< X-Application-Context: application:8007
< Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
< 
* Connection #1 to host test.com left intact
```

 - `add_header` `sends headers` `to client (browser)`, 
 - `proxy_set_header` `sends headers` `to backend server` (the one you proxy_pass to)


###     Why use proxy_set_header?
[Explain proxy_set_header](https://www.simplicidade.org/notes/2011/02/15/tip-keep-the-host-header-via-nginx-proxy_pass/)

- For short, the `header is rewritten to whatever value you use` `as the host in the URL given` `to the proxy_pass directive`.

- Example:
```
server {
    server_name my.site.com;

    location / {
        proxy_pass http://127.0.0.1:9999/;
    }
}
```

    - This will `proxy the request to your Web app` `running at 127.0.0.1, port 9999`
    - The problem is that the `Host HTTP header is rewritten to 127.0.0.1`

- In fact, the `header is rewritten to whatever value you use` `as the host in the URL given` `to the proxy_pass directive`.

- To `force the original Host header to be sent to the backend server`, like this:
```
server {
    server_name my.site.com;

    location / {
        proxy_pass http://127.0.0.1:9999/;
        proxy_set_header Host $http_host;
    }
}
```

- With this configuration, the backend server will receive whatever Host HTTP header your browser sent that matched this server block, which is particularly useful if you use a regular expression to match host names.

# Index of nginx variable:
[ngx_http_core module](http://nginx.org/en/docs/http/ngx_http_core_module.html#var_host)
##  $host
- in this order of precedence:
    + 1: host name from the request line, or 
    + 2: host name from the “Host” request header field, or 
    + 3: the server name matching a request

##  $http_name
- arbitrary request header field; the last part of a variable name is the field name converted to lower case with dashes replaced by underscores 
- A dictionary containing all available HTTP headers. Available headers depend on the client and server, but here are some examples:
```
    CONTENT_LENGTH – The length of the request body (as a string).
    CONTENT_TYPE – The MIME type of the request body.
    HTTP_ACCEPT – Acceptable content types for the response.
    HTTP_ACCEPT_ENCODING – Acceptable encodings for the response.
    HTTP_ACCEPT_LANGUAGE – Acceptable languages for the response.
    HTTP_HOST – The HTTP Host header sent by the client.
    HTTP_REFERER – The referring page, if any.
    HTTP_USER_AGENT – The client’s user-agent string.
    QUERY_STRING – The query string, as a single (unparsed) string.
    REMOTE_ADDR – The IP address of the client.
    REMOTE_HOST – The hostname of the client.
    REMOTE_USER – The user authenticated by the Web server, if any.
    REQUEST_METHOD – A string such as "GET" or "POST".
    SERVER_NAME – The hostname of the server.
    SERVER_PORT – The port of the server (as a string).
```

###     'HTTP_HOST' => $http_host 
- contains the content of the HTTP “Host” header field, if it was present in the request

##  $request_uri
- full `original request URI (with arguments)`

##  $scheme
- request scheme, “http” or “https”

##  $server_name
- name of the server which accepted a request 
