[nginx location example](https://www.thegeekstuff.com/2017/05/nginx-location-examples/)
[nginx location](http://nginx.org/en/docs/http/ngx_http_core_module.html#location)

# 5. location /test/ behaviour vs location /test behaviour
- If a location is defined by a prefix string that ends with the slash character, and requests are processed by one of proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, memcached_pass, or grpc_pass, then the special processing is performed. In response to a request with URI equal to this string, 

- but `without the trailing slash`, a `permanent redirect with the code 301` will be `returned to the requested URI with the slash appended`. If this is not desired, an exact match of the URI and location could be defined like this:
```
location /user/ {
    proxy_pass http://user.example.com;
}

user access abc.com/user -> 301 -> abc.com/user/ -> proxy_pass http://user.example.com
user access abc.com/user/test -> proxy_pass http://user.example.comtest =>> fail case
```

- if you don't want redirect you could use:
```
location = /product {
    proxy_pass http://backend;
}
```

- Here is an example with trailing slash in location, but `no trailing slash in proxy_pass`.
```
location /one/ {
    proxy_pass http://127.0.0.1:8080/two;
    ...
}

user access "http://yourserver.com/one/path/here?param=1" 
nginx will proxy request to http://127.0.0.1/twopath/here?param=1.
```