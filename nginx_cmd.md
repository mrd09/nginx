# Nginx 

## 1. Install NGINX Open Source:

- Install NGINX Open Source:
```
$ sudo apt-get remove nginx-common
$ sudo apt-get update
$ sudo apt-get install nginx
```

- Start NGINX Open Source:
```
$ sudo nginx
```

- Verify that NGINX Open Source is up and running:
```
$ curl -I 127.0.0.1
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 12 Dec 2018 03:01:37 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 11 Dec 2018 11:40:57 GMT
Connection: keep-alive
ETag: "5c0fa249-264"
Accept-Ranges: bytes


$ curl 127.0.0.1

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

```


## 2. nginx Command:

NAME
     nginx — HTTP and reverse proxy server, mail proxy server

SYNOPSIS
     nginx [-?hqTtVv] [-c file] [-g directives] [-p prefix] [-s signal]

DESCRIPTION
     nginx (pronounced “engine x”) is an HTTP and reverse proxy server, as well as a mail proxy
     server.  It is known for its high performance, stability, rich feature set, simple configura‐
     tion, and low resource consumption.
```
     The options are as follows:

     -s signal      Send a signal to the master process.  The argument signal can be one of: stop,
                    quit, reopen, reload.  The following table shows the corresponding system sig‐
                    nals:

                    stop    SIGTERM
                    quit    SIGQUIT
                    reopen  SIGUSR1
                    reload  SIGHUP

     -t             Do not run, just test the configuration file.  nginx checks the configuration
                    file syntax and then tries to open files referenced in the configuration file.     
```

## 3. Basic Functionality:
### 3.1. Controlling NGINX Processes at Runtime:
#### 3.1.1. Master and Worker Processes:
    + NGINX has **one master process** and **one or more worker processes**. 

- If *caching is enabled*, the **cache loader and cache manager processes** also *run at startup*.

- The main purpose of the *master process*:
    + **read and evaluate configuration files**
    + as well as **maintain the worker processes**.

- The **worker processes do the actual processing of requests**.

- **NGINX relies on OS-dependent mechanisms to efficiently distribute requests among worker processes**. 

- The number of worker processes:
    + is defined by the worker_processes directive in the nginx.conf 
    + can be set to a fixed number
    + or  configured to adjust automatically to the number of available CPU cores.
- Showing the master and worker process:    
```
$ ps axw -o pid,ppid,user,%cpu,vsz,wchan,command | egrep '(nginx|PID)'
  PID  PPID USER     %CPU    VSZ WCHAN  COMMAND
 8264  5982 mrd09     0.0  23076 pipe_w grep -E --color=auto (nginx|PID)
28978     1 root      0.0 140628 -      nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
28981 28978 www-data  0.0 143304 -      nginx: worker process
28983 28978 www-data  0.0 143304 -      nginx: worker process
28985 28978 www-data  0.0 143304 -      nginx: worker process
28986 28978 www-data  0.0 143304 -      nginx: worker process
```

#### 3.1.2. Controlling NGINX:
- **To reload your configuration** => *you can **stop or restart NGINX, or send signals to the master process***. 

- A *signal can be sent by running the nginx cmd* (invoking the NGINX executable) with the **-s argument** :
```
nginx -s <SIGNAL>

where <SIGNAL> can be one of the following:

    quit – Shut down gracefully
    reload – Reload the configuration file => only reload the config if fail
    reopen – Reopen log files
    stop – Shut down immediately (fast shutdown)
```
- **reload: Reloading is safer than restarting:** because of this behaviors:
    - In order for nginx to **re-read the conf file**, a **HUP signal should be sent to the *master process***. 
    - The **master process first checks the syntax validity, then tries to apply new configuration**, that is, to open log files and new listen sockets. 
        + *If this fails*, 
            + it **rolls back changes and continues to work with old configuration(with old worker processes)**. 

        + *If this succeeds*, 
            + it starts new worker processes, and sends messages to old worker processes requesting them to shut down gracefully. 
            + Old worker processes close listen sockets and continue to service old clients. After all clients are serviced, old worker processes are shut down. 

```
- If config fail nginx wont reload the config:
Dec 12 10:26:36 mrd09 systemd[1]: nginx.service: Control process exited, code=exited status=1
Dec 12 10:26:36 mrd09 systemd[1]: Reload failed for A high performance web server and a reverse proxy

- If config syntax check of, nginx will reload the worker process
11:14 $ ps axw -o pid,ppid,user,%cpu,vsz,wchan,command | egrep '(nginx|PID)'
  PID  PPID USER     %CPU    VSZ WCHAN  COMMAND
 8938  5982 mrd09     0.0  23076 pipe_w grep -E --color=auto (nginx|PID)
28978     1 root      0.0 140628 -      nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
28981 28978 www-data  0.0 143304 -      nginx: worker process
28983 28978 www-data  0.0 143304 -      nginx: worker process
28985 28978 www-data  0.0 143304 -      nginx: worker process
28986 28978 www-data  0.0 143304 -      nginx: worker process
✔ ~ 
11:14 $ ps axw -o pid,ppid,user,%cpu,vsz,wchan,command | egrep '(nginx|PID)'
  PID  PPID USER     %CPU    VSZ WCHAN  COMMAND
 8970 28978 www-data  0.0 143440 -      nginx: worker process
 8971 28978 www-data  0.0 143440 -      nginx: worker process
 8972 28978 www-data  0.0 143440 -      nginx: worker process
 8973 28978 www-data  0.0 143440 -      nginx: worker process
 8986  5982 mrd09     0.0  23076 pipe_w grep -E --color=auto (nginx|PID)
28978     1 root      0.0 140764 -      nginx: master process /usr/sbin/nginx -g daemon on; master_process on;

```

### 3.2. Creating NGINX Plus and NGINX Configuration Files:
- Nginx config : text‑based configuration file written in a particular format. 
- By default the **config file is named nginx.conf** and for NGINX Plus is **placed in the /etc/nginx directory**.

#### 3.2.1. Directives:
- **Config struture:**
    + Consists of **directives(keyword) and their parameters.** 
    + **Simple (single‑line) directives each end with a semicolon(;)**.
    + Other directives act as **“containers” that group together related directives, enclosing them in curly braces ( {} )**

- Config Example:
```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}
```

#### 3.2.3. Feature-Specific Configuration Files : 
- To make the configuration easier to maintain:
    + **we recommend that you split it into a set of feature‑specific files stored in the /etc/nginx/conf.d directory** 
    + and use the directive     :    **include**  in the main nginx.conf file *to **reference** the contents of the feature‑specific files*.
```
include conf.d/http;
include conf.d/stream;
include conf.d/exchange-enhanced;
```

#### 3.2.4. Contexts
- A few **top‑level directives**, referred to as contexts, group together the directives that apply to different traffic types:
    + **events**  – General connection processing
    + **http**    –  HTTP traffic
    + **mail**    –  Mail traffic
    + **stream**  – TCP and UDP traffic

#### 3.2.5. Virtual Servers
- In each of the traffic‑handling contexts, **you include one or more server blocks to define virtual servers that control the processing of requests**. The directives you can include within a server context vary depending on the traffic type.

- **For HTTP traffic (the http context)**, 
  + each server directive controls the **processing of requests for resources at particular domains or IP addresses**. One or more location contexts in a server context define how to process specific sets of URIs.

- **For mail and TCP/UDP traffic (the mail and stream contexts)** 
  + the server directives each control the **processing of traffic arriving at a particular TCP port or UNIX socket**.

#### 3.2.6. Sample Configuration File with Multiple Contexts
- Example and explain:
```
user nobody; # a directive in the 'main' context

events {
    # configuration of connection processing
}

http {
    # Configuration specific to HTTP and affecting all virtual servers  

    server {
        # configuration of HTTP virtual server 1       
        location /one {
            # configuration for processing URIs starting with '/one'
        }
        location /two {
            # configuration for processing URIs starting with '/two'
        }
    } 
    
    server {
        # configuration of HTTP virtual server 2
    }
}

stream {
    # Configuration specific to TCP/UDP and affecting all virtual servers
    server {
        # configuration of TCP virtual server 1 
    }
}

```

#### 3.2.7. Reloading Configuration

- **For changes to the configuration file to take effect, it must be reloaded.** 
- *You can either restart the nginx process or send the reload signal* to **upgrade the configuration without interrupting the processing of current requests**.

## 4. Web server:
### 4.1. Serving Static Content

- This section describes 
  + how to configure NGINX and NGINX Plus to serve static content, 
  + how to define which paths are searched to find requested files, 
  + how to set up index files, and 
  + how to tune NGINX and NGINX Plus, as well as the kernel, for optimal performance.

#### 4.1.1. Root Directory and Index Files
- The **root** directive *specifies the root directory that will be used to search for a file.* To obtain the path of a requested file, NGINX appends the request URI to the path specified by the root directive. The directive can be placed on any level within the **http {}, server {}, or location {}** contexts. In the example below, the root directive is defined for a virtual server. It applies to all location {} blocks where the root directive is not included to explicitly redefine the root:
- Example:
```
server {
    root /www/data;

    location / {
    }

    location /images/ {
    }

    location ~ \.(mp3|mp4) {
        root /www/media;
    }
}
```

#### 4.1.2. NGINX Reverse Proxy
- This article describes the basic configuration of a proxy server. 
- You will learn 
  + how to pass a request from NGINX to proxied servers over different protocols,
  + modify client request headers that are sent to the proxied server, 
  + and configure buffering of responses coming from the proxied servers.

##### 4.1.2.1. Introduction

- Proxying is typically used to 
  + distribute the load among several servers, 
  + seamlessly show content from different websites, or 
  + pass requests for processing to application servers over protocols other than HTTP.

- Passing a Request to a Proxied Server:
    + When NGINX proxies a request, it sends the request to a specified proxied server, fetches the response, and sends it back to the client. 
    + It is possible to proxy requests to an HTTP server (another NGINX server or any other server) 
    + or a non-HTTP server (which can run an application developed with a specific framework, such as PHP or Python) using a specified protocol. Supported protocols include FastCGI, uwsgi, SCGI, and memcached.

- **To pass a request to an HTTP proxied server**, the **proxy_pass** directive is *specified inside a* **location**. For example:
```
server {
    listen              {{ keepalived.internal_vip | default(internal_ip_addr) }}:443 ssl;
    server_name         {{ anv2.operation_domain }};
    ssl_certificate     /etc/nginx/ssl/{{ anv2.operation_domain }}/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/{{ anv2.operation_domain }}/privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_authentication.host }}:{{ anv2.wallet_authentication.port }}/;
    }

    location /customer/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.acquire_agent.host }}:{{ anv2.acquire_agent.port }}/;
        client_max_body_size    20M;
    }

    location /setting/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.management_user.host }}:{{ anv2.management_user.port }}/;
    }

    location /operation/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.inventory_frontend.host }}:{{ anv2.inventory_frontend.port }}/;
    }

    location /provider/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_service_frontend.host }}:{{ anv2.wallet_service_frontend.port }}/provider/;
    }
    ...
server {
    listen      {{ keepalived.internal_vip | default(internal_ip_addr) }}:80;
    server_name {{ anv2.operation_domain }};
    return      301 https://$host$request_uri;
}
```
- Variable from group_vars/bizdev:
```
- group_vars/bizdev
  wallet_authentication:
    host: "{{ groups['anv2-wallet-authentication'][0] }}"
    port: 11205

- inventory: bizdev
[anv2-wallet-authentication]
172.30.2.12

- group_vars/bizdev
  acquire_agent:
    host: "{{ groups['anv2-acquire-agent'][0] }}"
    port: 11240

server {
    listen      {{ keepalived.internal_vip | default(internal_ip_addr) }}:80;
=> in group_var/bizdev: keepalived.internal_vip  doesn't exist/define
=> So will use default(internal_ip_addr)
=> in group_var/bizdev: internal_ip_addr  doesn't exist/define
=> So with the default variable precedence: ansible will check in inventory "bizdev" for "internal_ip_addr" :
  => so group host proxy: has 2 value for "internal_ip_addr" :  172.30.1.41, 172.30.1.42
  => It will take 1 IP at the time

```
- To pass a request to a **non-HTTP proxied server**, the appropriate \*\*\_pass directive should be used:
```
    fastcgi_pass passes a request to a FastCGI server
    uwsgi_pass passes a request to a uwsgi server
    scgi_pass passes a request to an SCGI server
    memcached_pass passes a request to a memcached server
```


### X. Common Modules:
#### X.1. ngx_http_core_module:
##### X.1.1 server:
- Sets configuration for a virtual server. There is no clear separation between IP-based (based on the IP address) and name-based (based on the “Host” request header field) virtual servers. Instead, the listen directives describe all addresses and ports that should accept connections for the server, and the server_name directive lists all server names. Example configurations are provided in the “How nginx processes a request” document. 
```
Syntax:   server { ... }
Default:  —
Context:  http
```
- Name-based virtual servers:
```
server {
    listen      80;
    server_name example.org www.example.org;
    ...
}
```

- Mixed name-based and IP-based virtual servers:
```
server {
    listen      192.168.1.1:80;
    server_name example.org www.example.org;
    ...
}
```

##### X.1.2 server_name:
- Set server_name:
```
Syntax:   server_name name ...;
Default:  

server_name "";

Context:  server
```
- Sets names of a virtual server, for example:
```
    server {
        server_name example.com www.example.com;
    }
```
  + **The first name becomes the primary server name**.

- Server names can include an asterisk (“*”) replacing the first or last part of a name:
```
    server {
        server_name example.com *.example.com www.example.*;
    }
```
  + Such names are called wildcard names.

- The first two of the names mentioned above can be combined in one:
```
    server {
        server_name .example.com;
    }
```

##### X.1.3 listen:
- Sets the address and port for IP, or the path for a UNIX-domain socket on which the server will accept requests. Both address and port, or only address or only port can be specified. An address may also be a hostname
```
Syntax:   listen address[:port] [default_server] [ssl] [http2 | spdy] [proxy_protocol] [setfib=number] [fastopen=number] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [ipv6only=on|off] [reuseport] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
listen port [default_server] [ssl] [http2 | spdy] [proxy_protocol] [setfib=number] [fastopen=number] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [ipv6only=on|off] [reuseport] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
listen unix:path [default_server] [ssl] [http2 | spdy] [proxy_protocol] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
Default:  

listen *:80 | *:8000;

Context:  server
```
- For example:
```
server {
    listen 127.0.0.1:8000;
    listen 127.0.0.1 | 192.168.1.27;
    listen 8000;
    listen *:8000;
    listen localhost:8000;
    ...
}    
```

##### X.1.4 location:
- Sets configuration depending on a request URI.
- The matching is performed against a normalized URI, after decoding the text encoded in the “%XX” form, resolving references to relative path components “.” and “..”, and possible compression of two or more adjacent slashes into a single slash. 
```
Syntax:   location [ = | ~ | ~* | ^~ ] uri { ... }
location @name { ... }
Default:  —
Context:  server, location
```
-  Let’s illustrate the above by an example:
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
- The “/” request will match configuration A, the “/index.html” request will match configuration B, the “/documents/document.html” request will match configuration C, the “/images/1.gif” request will match configuration D, and the “/documents/1.jpg” request will match configuration E.

- The “@” prefix defines a named location. Such a location is not used for a regular request processing, but instead used for request redirection. They cannot be nested, and cannot contain nested locations. 

#### X.2. ngx_http_ssl_module:
##### X.2.1. ssl_certificate:
- Specifies a file with the certificate in the PEM format for the given virtual server. If intermediate certificates should be specified in addition to a primary certificate, they should be specified in the same file in the following order: the primary certificate comes first, then the intermediate certificates. A secret key in the PEM format may be placed in the same file. 
```
Syntax:   ssl_certificate file;
Default:  —
Context:  http, server
```
- Example:
```
server {
    listen              443 ssl;
    server_name         example.com;

    ssl_certificate     example.com.rsa.crt;
    ssl_certificate_key example.com.rsa.key;
    ...
}

```

##### X.2.2. ssl_certificate:
- Specifies a file with the secret key in the PEM format for the given virtual server. 
```
Syntax:   ssl_certificate_key file;
Default:  —
Context:  http, server
```

- Example:
```
server {
    listen              443 ssl;
    server_name         example.com;

    ssl_certificate     example.com.rsa.crt;
    ssl_certificate_key example.com.rsa.key;
    ...
}

```

#### X.3. ngx_http_headers_module:
##### X.3.1. add_header:
- Adds the specified field to a response header provided that the response code equals 200, 201 (1.3.10), 204, 206, 301, 302, 303, 304, 307 (1.1.16, 1.0.13), or 308 (1.13.0). The value can contain variables. 
```
Syntax:   add_header name value [always];
Default:  —
Context:  http, server, location, if in location
```

- Example:
```
server {
    listen              {{ keepalived.internal_vip | default(internal_ip_addr) }}:443 ssl;
    server_name         {{ anv2.operation_domain }};
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
...
```

#### X.4. ngx_core_module:
##### X.4.1. include:
- Includes another file, or files matching the specified mask, into configuration. Included files should consist of syntactically correct directives and blocks
```
Syntax:   include file | mask;
Default:  —
Context:  any
```

#### X.5. ngx_http_proxy_module:
##### X.5.1. proxy_pass:
- Sets the protocol and address of a proxied server:
```
Syntax:   proxy_pass URL;
Default:  —
Context:  location, if in location, limit_except
```
- Sets the protocol and address of a proxied server and an optional URI to which a location should be mapped. As a protocol, “http” or “https” can be specified. The address can be specified as a domain name or IP address, and an optional port:
```
    proxy_pass http://localhost:8000/uri/;
```
or as a UNIX-domain socket path specified after the word “unix” and enclosed in colons:
```
    proxy_pass http://unix:/tmp/backend.socket:/uri/;
```
- Example:
```
    location /operation/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.inventory_frontend.host }}:{{ anv2.inventory_frontend.port }}/;
    }

```

### X. Configuration Examples:
```
$ cat templates/nginx/an_wallet.conf.j2 
#jinja2: trim_blocks: "true", lstrip_blocks: "true"
# {{ ansible_managed }}

server {
    listen              {{ keepalived.internal_vip | default(internal_ip_addr) }}:443 ssl;
    server_name         {{ anv2.operation_domain }};
    ssl_certificate     /etc/nginx/ssl/{{ anv2.operation_domain }}/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/{{ anv2.operation_domain }}/privkey.pem;
    add_header          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_authentication.host }}:{{ anv2.wallet_authentication.port }}/;
    }

    location /customer/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.acquire_agent.host }}:{{ anv2.acquire_agent.port }}/;
        client_max_body_size    20M;
    }

    location /setting/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.management_user.host }}:{{ anv2.management_user.port }}/;
    }

    location /operation/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.inventory_frontend.host }}:{{ anv2.inventory_frontend.port }}/;
    }

    location /provider/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_service_frontend.host }}:{{ anv2.wallet_service_frontend.port }}/provider/;
    }

    location /wallet/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_service_frontend.host }}:{{ anv2.wallet_service_frontend.port }}/wallet/;
    }

    location /service/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_service_frontend.host }}:{{ anv2.wallet_service_frontend.port }}/service/;
    }

    location /assets/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.wallet_service_frontend.host }}:{{ anv2.wallet_service_frontend.port }}/assets/;
    }

    location /store/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.epin_store_frontend.host }}:{{ anv2.epin_store_frontend.port }}/store/;
        client_max_body_size    50M;
        proxy_send_timeout      90;
        send_timeout            600;
        proxy_read_timeout      90;
    }

    location /store-offline/ {
        include              /etc/nginx/proxy_params;
        proxy_pass           http://{{ anv2.epin_store_offline_frontend.host }}:{{ anv2.epin_store_offline_frontend.port }}/store-offline/;
        client_max_body_size    50M;
        proxy_send_timeout      90;
        send_timeout            600;
        proxy_read_timeout      90;
    }

}

server {
    listen      {{ keepalived.internal_vip | default(internal_ip_addr) }}:80;
    server_name {{ anv2.operation_domain }};
    return      301 https://$host$request_uri;
}
```