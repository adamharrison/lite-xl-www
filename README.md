# lite-xl-www

A simple library that provides a web client to fetch, and submit data via HTTP(S)
requests.

Functions via lite-xl's coroutine mechanism. Normally, when a request is
submitted, it will be transferred in the background, and until it is ready,
will continually yield within the coroutine. If you submit a request outside
a coroutine, the request will block the editor, but is still feasible to submit
in cases where that is not an issue.

## Building

To build the library, from scratch, do:

```sh
git clone --depth=1 https://github.com/adamharrison/lite-xl-www.git && \
  cd lite-xl-www && git submodule update --init && build.sh
```

This should spit out a shared library on linux, windows (msys2), macos and android.

## Sample Basic Usage

See below an example:

```lua
local www = require "libraries.www"

core.add_thread(function()
  local agent = www.new()
  print(agent:get("https://google.com"))
  print(agent:post("https://google.com", "q=test"))
end)
```

## Sample Advanced Usage

For a more nitty-gritty experience, you can use the core method `request`, which
uses a stateless interface, and will return you the raw request of what you
request, no redirection, decoding, or anything else.

The only shared state present is the underlying queue that handles making
the requests, and the SSL configuration. Everything else is stateless.

```lua
local www = require "libraries.www"

core.add_thread(function()
  local res = www.request({
    url = "https://google.com",
    headers = { connection = "close" }
  })
  print(res.code)
  print(res.status)
  for k,v in pairs(res.headers) do
    print(k, v)
  end
  print(res.body)
end)
```

In the case where you want to retrieve, or submit a large document, you can
do things via chunks.

```lua
local www = require "libraries.www"

core.add_thread(function()
  local f = io.open("mylargefile")
  local res = www.request({
    url = "https://google.com",
    method = "POST",
    body = function()
      return f:read(4096)
    end
  })
  print(res.status)
end)
```

And, the inverse, for the download:

```lua
local www = require "libraries.www"

core.add_thread(function()
  local f = io.open("mylargefile", "wb")
  www.request({
    url = "https://google.com",
    response = function(response, chunk)
      print(response.status)
      f:write(chunk)
    end
  })
end)
```
