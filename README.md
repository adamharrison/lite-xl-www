# lite-xl-www

A simple library that provides a web client to fetch, and submit data via HTTP(S) requests.

Functions via lite-xl's coroutine mechanism. Normally, when a request is submitted, it will be transferred in the background, and until it is ready, will continually yield within the coroutine. If you submit a request outside a coroutine,
the request will block the editor, but is still feasible to submit in cases where that is not an issue.

## Sample Usage

See below an example:

```lua
local www = require "www"

core.add_thread(function()
  local res = www.request({ url = "https://google.com", headers = { connection = "close" } })
  print(res.code)
  print(res.status)
  for k,v in pairs(res.headers) do
    print(k, v)
  end
  print(res.body)
end)
```

In the case where you want to retrieve, or submit a large document, you can do things via chunks.

```lua
local www = require "www"

core.add_thread(function()
  local f = io.open("mylargefile")
  local res = www.request({ url = "https://google.com", method = "POST", body = function()
    return f:read(4096)
  end })
  print(res.status)
end)
```

And, the inverse, for the download:

```lua
local www = require "www"

core.add_thread(function()
  local f = io.open("mylargefile", "wb")
  www.request({ url = "https://google.com", callback = function(response, chunk)
    print(response.status)
    f:write(chunk)
  end })
end)
```
