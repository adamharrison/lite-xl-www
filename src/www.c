#if _WIN32
  #include <direct.h>
  #include <winsock2.h>
  #include <windows.h>
#else
  #include <pthread.h>
  #include <netdb.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/net.h>
#ifdef MBEDTLS_DEBUG_C
  #include <mbedtls/debug.h>
#endif

#ifdef WWW_STANDALONE
  #include <lua.h>
  #include <lauxlib.h>
  #include <lualib.h>
#else
  #define LITE_XL_PLUGIN_ENTRYPOINT
  #include <lite_xl_plugin_api.h>
#endif


#define MAX_REQUEST_HEADER_SIZE 4096
#define MAX_HOSTNAME_SIZE 256
#define MAX_PROTOCOL_SIZE 6
#define MAX_PATH_SIZE 1024
#define MAX_METHOD_SIZE 10
#define MAX_ERROR_SIZE 1024
#define MAX_RESPONSE_CHUNK 4096
#define YIELD_TIMEOUT 0.01
#define MAX_TIMEOUT 5

typedef struct {
  #if _WIN32
    HANDLE thread;
    void* (*func)(void*);
    void* data;
  #else
    pthread_t thread;
  #endif
} thread_t;

typedef struct {
  #if _WIN32
    HANDLE mutex;
  #else
    pthread_mutex_t mutex;
  #endif
} mutex_t;

int sleep_in_miliseconds(int miliseconds) {
  #if _WIN32
    Sleep(miliseconds);
  #else
    usleep(miliseconds * 1000);
  #endif
}


static mutex_t* new_mutex() {
  mutex_t* mutex = malloc(sizeof(mutex_t));
  #if _WIN32
    mutex->mutex = CreateMutex(NULL, FALSE, NULL);
  #else
    pthread_mutex_init(&mutex->mutex, NULL);
  #endif
  return mutex;
}

static mutex_t* free_mutex(mutex_t* mutex) {
  #if _WIN32
    CloseHandle(mutex->mutex);
  #else
    pthread_mutex_destroy(&mutex->mutex);
  #endif
  free(mutex);
}

static int lock_mutex(mutex_t* mutex) {
  #if _WIN32
    WaitForSingleObject(mutex->mutex, INFINITE);
  #else
    pthread_mutex_lock(&mutex->mutex);
  #endif
}

static int unlock_mutex(mutex_t* mutex) {
  #if _WIN32
    ReleaseMutex(mutex->mutex)
  #else
    pthread_mutex_unlock(&mutex->mutex);
  #endif
}

static mbedtls_x509_crt x509_certificate;
static mbedtls_entropy_context entropy_context;
static mbedtls_ctr_drbg_context drbg_context;
static mbedtls_ssl_config ssl_config;
static int no_verify_ssl;

static int is_main_thread(lua_State* L) {
  int is_main = lua_pushthread(L);
  lua_pop(L, 1);
  return is_main;
}

static void* www_request_thread_callback(void* data);

#if _WIN32
static DWORD windows_thread_callback(void* data) {
  thread_t* thread = data;
  thread->data = thread->func(thread->data);
  return 0;
}
#endif

static thread_t* create_thread(void* (*func)(void*), void* data) {
  thread_t* thread = malloc(sizeof(thread_t));
  #if _WIN32
    thread->func = func;
    thread->data = data;
    thread->thread = CreateThread(NULL, 0, windows_thread_callback, thread, 0, NULL);
  #else
    pthread_create(&thread->thread, NULL, func, data);
  #endif
  return thread;
}

static void* join_thread(thread_t* thread) {
  void* retval;
  #if _WIN32
    WaitForSingleObject(thread->thread, INFINITE);
  #else
    pthread_join(thread->thread, &retval);
  #endif
  free(thread);
  return retval;
}

typedef enum {
  REQUEST_STATE_INIT,
  REQUEST_STATE_SEND_HEADERS,
  REQUEST_STATE_SEND_BODY,
  REQUEST_STATE_RECV_HEADERS,
  REQUEST_STATE_RECV_PROCESS_HEADERS,
  REQUEST_STATE_RECV_BODY,
  REQUEST_STATE_RECV_COMPLETE,
  REQUEST_STATE_ERROR
} request_type_e;

typedef struct request_t {
  int socket;
  char hostname[MAX_HOSTNAME_SIZE];
  char chunk[MAX_REQUEST_HEADER_SIZE];
  size_t chunk_length;
  int is_get;
  int is_ssl;
  int body_length;
  int body_transmitted;
  int verbose;
  time_t last_activity;
  unsigned short port;
  request_type_e state;
  mbedtls_net_context net_context;
  mbedtls_ssl_context ssl_context;
  struct request_t* prev;
  struct request_t* next;
} request_t;

/*
Takes in a table that describes your request:
{
  url = string
  body = string | function(body_length) | nil
  method = string
  headers = string[string]
  version = "1.1",
  progress = function(chunk) | nil,
  callback = function(response, chunk) | nil
}
Will act as a blocking request in cases of the main thread, and will yield in case of a coroutine. Will return a table that
contains the following:
{
  headers = table
  body = string
},

unless `response` is non-nil, in which case, body will be nil, and the response function will handle everything.

*/

static thread_t* www_thread;
static mutex_t* www_mutex;
static request_t* request_queue;

static int min(int a, int b) { return a < b ? a : b; }
static int lua_objlen(lua_State* L, int idx) {
  lua_len(L, idx);
  int n = lua_tointeger(L, -1);
  lua_pop(L, 1);
  return n;
}

static request_t* request_enqueue(const char* hostname, unsigned short port, const char* header, int header_length, int is_ssl, int is_get, int verbose) {
  lock_mutex(www_mutex);
  request_t* request = calloc(sizeof(request_t), 1);
  request->socket = -1;
  strncpy(request->hostname, hostname, MAX_HOSTNAME_SIZE);
  strncpy(request->chunk, header, min(header_length, MAX_REQUEST_HEADER_SIZE));
  request->chunk_length = header_length;
  request->is_ssl = is_ssl;
  request->is_get = is_get;
  request->state = REQUEST_STATE_INIT;
  request->body_length = -1;
  request->port = port;
  request->verbose = verbose;
  if (is_ssl) {
    mbedtls_ssl_init(&request->ssl_context);
    mbedtls_net_init(&request->net_context);
  }
  if (!request_queue) {
    www_thread = create_thread(www_request_thread_callback, NULL);
  } else {
    request_queue->prev = request;
    request->next = request_queue;
  }
  request_queue = request;
  unlock_mutex(www_mutex);
  return request;
}


static void request_complete(request_t* request) {
  if (request->prev)
    request->prev->next = request->next;
  else
    request_queue = request->next;
  if (request->next)
    request->next->prev = request->prev;
  if (request->is_ssl) {
    mbedtls_ssl_free(&request->ssl_context);
    mbedtls_net_free(&request->net_context);
  }
  if (request->socket != -1)
    close(request->socket);
  free(request);
}

static int www_requestk(lua_State* L, int status, lua_KContext ctx) {
  int request_response_table_index;
  if (ctx) // Coroutine.
    lua_rawgeti(L, LUA_REGISTRYINDEX, (int)ctx);
  request_response_table_index = lua_gettop(L);
  lua_getfield(L, request_response_table_index, "request");
  luaL_checktype(L, -1, LUA_TLIGHTUSERDATA);
  int has_error = 0;
  request_t* request = (request_t*)lua_touserdata(L, -1);
  do {
    lock_mutex(www_mutex);
      time_t current_time = time(NULL);
      switch (request->state) {
        case REQUEST_STATE_SEND_BODY:
          lua_getfield(L, 1, "body");
          switch (lua_type(L, -1)) {
            case LUA_TSTRING:
              size_t len;
              const char* buffer = lua_tolstring(L, -1, &len);
              request->body_length = len;
              memcpy(&request->chunk[request->chunk_length], &buffer[request->body_transmitted], min(sizeof(request->chunk) - request->chunk_length, len - request->body_transmitted));
            break;
            case LUA_TFUNCTION:
            default: {
              lua_pushfstring(L, "error transmitting body; body must be either a string or a callback function", lua_typename(L, lua_type(L, -1))); has_error = 1;
              goto error;
            }
          }
          lua_pop(L, 1);
        break;
        case REQUEST_STATE_RECV_PROCESS_HEADERS: {
          const char* code_delim = strpbrk(request->chunk, " ");
          const char* status_delim = code_delim ? strpbrk(code_delim + 1, " ") : NULL;
          const char* eol = status_delim ? strstr(status_delim + 1, "\r\n") : NULL;
          if (!code_delim || !status_delim || strncmp(request->chunk, "HTTP/1.1", 8) != 0 || !eol) {
            lua_pushfstring(L, "error processing headers: %s", request->chunk); has_error = 1;
            goto error;
          }
          int code = atoi(code_delim + 1);
          char status_line[128];
          strncpy(status_line, status_delim + 1, min(eol - status_delim - 1, sizeof(status_line)));
          lua_getfield(L, request_response_table_index, "response");
          lua_pushinteger(L, code);
          lua_setfield(L, -2, "code");
          lua_pushstring(L, status_line);
          lua_setfield(L, -2, "status");
          lua_newtable(L);
          char* header_start = strstr(request->chunk, "\r\n") + 2;
          while (1) {
            if (header_start) {
              if (header_start[0] == '\r' && header_start[1] == '\n') {
                header_start += 2;
                break;
              }
            }
            char* value_offset = strstr(header_start, ":");
            char* header_end = strstr(header_start, "\r\n");
            if (value_offset > header_end) {
              lua_pushfstring(L, "error processing headers: %s", request->chunk); has_error = 1;
              goto error;
            }
            int header_name_length = value_offset - header_start;
            for (int i = 0; i < header_name_length; ++i)
              header_start[i] = tolower(header_start[i]);
            if (strncmp(header_start, "content-length", 14) == 0)
              request->body_length = atoi(value_offset);
            lua_pushlstring(L, header_start, header_name_length);
            for (value_offset = value_offset + 1; *value_offset == ' '; ++value_offset);
            lua_pushlstring(L, value_offset, header_end - value_offset);
            lua_rawset(L, -3);
            header_start = header_end + 2;
          }
          lua_setfield(L, -2, "headers");
          size_t header_length = request->chunk_length - (header_start - request->chunk);
          memmove(request->chunk, header_start, header_length);
          request->chunk_length -= header_length;
          request->body_transmitted = request->chunk_length;
          request->state = REQUEST_STATE_RECV_BODY;
          lua_pop(L, 1);
        // deliberate fallthrough.
        case REQUEST_STATE_RECV_BODY:
          if (request->chunk_length) {
            lua_getfield(L, request_response_table_index, "callback");
            if (lua_type(L, -1) == LUA_TFUNCTION) {
              lua_getfield(L, request_response_table_index, "response");
              lua_pushlstring(L, request->chunk, request->chunk_length);
              if (lua_pcall(L, 2, 0, 0)) {
                size_t len;
                const char* err = lua_tolstring(L, -1, &request->chunk_length);
                strncpy(request->chunk, err, sizeof(request->chunk));
                request->state = REQUEST_STATE_ERROR;
              }
              request->chunk_length = 0;
            } else {
              lua_pop(L, 1);
              lua_getfield(L, request_response_table_index, "response");
              lua_getfield(L, -1, "body");
              if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                lua_newtable(L);
                lua_pushvalue(L, -1);
                lua_setfield(L, -3, "body");
              }
              lua_pushlstring(L, request->chunk, request->chunk_length);
              lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
              request->chunk_length = 0;
              lua_pop(L, 2);
            }
          }
          if (request->body_transmitted >= request->body_length) {
            lua_getfield(L, request_response_table_index, "response");
            lua_getfield(L, -1, "body");
            if (lua_type(L, -1) == LUA_TTABLE) {
              int n = lua_objlen(L, -1);
              luaL_Buffer b;
              luaL_buffinit(L, &b);
              for (int i = 1; i <= n; ++i) {
                lua_rawgeti(L, -1, i);
                size_t len;
                const char* chunk = lua_tolstring(L, -1, &len);
                luaL_addlstring(&b, chunk, len);
                lua_pop(L, 1);
              }
              luaL_pushresult(&b);
              lua_setfield(L, -3, "body");
            }
            lua_pop(L, 2);
            request->state = REQUEST_STATE_RECV_COMPLETE;
          }
        } break;
        default: break;
      }
    error:
    unlock_mutex(www_mutex);
    if (has_error) {
      size_t len;
      strncpy(request->chunk, lua_tolstring(L, -1, &len), sizeof(request->chunk));
      request->chunk_length = min(len, sizeof(request->chunk));
      request->state = REQUEST_STATE_ERROR;
    }
    if (!ctx)
      sleep_in_miliseconds(1);
  } while (!ctx && request->state != REQUEST_STATE_RECV_COMPLETE && request->state != REQUEST_STATE_ERROR);
  if (request->state == REQUEST_STATE_RECV_COMPLETE) {
    lock_mutex(www_mutex);
    request_complete(request);
    unlock_mutex(www_mutex);
    if (ctx)
      luaL_unref(L, LUA_REGISTRYINDEX, (int)ctx);
    lua_getfield(L, request_response_table_index, "response");
    return 1;
  } else if (request->state == REQUEST_STATE_ERROR) {
    lua_pop(L, 1);
    lua_pushfstring(L, "error in request: %s", request->chunk);
    lock_mutex(www_mutex);
    request_complete(request);
    unlock_mutex(www_mutex);
    return lua_error(L);
  } else {
    lua_pushnumber(L, YIELD_TIMEOUT);
    lua_yieldk(L, 1, ctx, www_requestk);
  }
  return 0;
}

static int f_www_request(lua_State* L) {
  long response_code;
  char method[MAX_METHOD_SIZE];
  char protocol[MAX_PROTOCOL_SIZE] = {0};
  char hostname[MAX_HOSTNAME_SIZE] = {0};
  char path[MAX_PATH_SIZE] = "/";
  char err[MAX_ERROR_SIZE] = {0};
  char header[MAX_REQUEST_HEADER_SIZE];
  const char* version = "HTTP/1.1";

  lua_getfield(L, 1, "url");
  const char* url = luaL_checkstring(L, -1);

  char* delim;

  if (!(delim = strpbrk(url, ":")) || (delim - url) >= 5)
    goto url_error;
  strncpy(protocol, url, (delim - url));
  if (strncmp(&delim[1], "//", 2) != 0)
    goto url_error;
  delim += 3;
  char* hostname_delim;
  if ((hostname_delim = strpbrk(delim, "/"))) {
    strncpy(hostname, delim, min(sizeof(hostname), hostname_delim - delim));
    strncpy(path, hostname_delim, sizeof(path));
  } else
    strncpy(hostname, delim, sizeof(hostname));

  url_error:
  if (!protocol[0] || !hostname[0] || !path[0])
      return luaL_error(L, "unable to parse URL %s", url);
  if (strcmp(protocol, "http") != 0 && strcmp(protocol, "https") != 0)
    return luaL_error(L, "unrecognized protocol");

  lua_pop(L, 1);
  lua_getfield(L, 1, "verbose");
  int verbose = lua_toboolean(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, 1, "body");
  int has_body = !lua_isnil(L, -1);
  lua_pop(L,1);
  lua_getfield(L, 1, "method");
  if (!lua_isnil(L, -1))
    strncpy(method, luaL_checkstring(L, -1), sizeof(method));
  else
    strcpy(method, has_body ? "POST" : "GET");
  lua_pop(L, 1);

  int is_get = strcmp(method, "GET") == 0;

  int header_offset = snprintf(header, sizeof(header), "%s %s %s\r\n", method, path, version);
  lua_getfield(L, 1, "headers");
  if (!lua_isnil(L, -1)) {
    lua_pushnil(L);
    while (lua_next(L, -2)) {
      if (header_offset < sizeof(header))
        header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "%s: %s\r\n", luaL_checkstring(L, -2), lua_tostring(L, -1));
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "Host: %s\r\n", hostname);
  header[header_offset++] = '\r';
  header[header_offset++] = '\n';
  header[header_offset++] = 0;
  int is_ssl = strcmp(protocol, "https") == 0;
  unsigned short port = is_ssl ? 443 : 80;
  request_t* request = request_enqueue(hostname, port, header, header_offset, is_ssl, is_get, verbose);
  lua_pushlightuserdata(L, request);
  lua_setfield(L, 1, "request");
  lua_newtable(L);
  lua_setfield(L, 1, "response");
  if (is_main_thread(L)) {
    www_requestk(L, 0, 0);
  } else {
    int r = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushnumber(L, 0);
    lua_yieldk(L, 1, (lua_KContext)r, www_requestk);
  }
  return 1;
}

static int mbedtls_snprintf(int mbedtls, char* buffer, int len, int status, const char* str, ...) {
  char mbed_buffer[256];
  mbedtls_strerror(status, mbed_buffer, sizeof(mbed_buffer));
  int error_len = mbedtls ? strlen(mbed_buffer) : strlen(strerror(status));
  va_list va;
  int offset = 0;
  va_start(va, str);
    offset = vsnprintf(buffer, len, str, va);
  va_end(va);
  if (offset < len - 2) {
    strcat(buffer, ": ");
    if (offset < len - error_len - 2)
      strcat(buffer, mbedtls ? mbed_buffer : strerror(status));
  }
  return strlen(buffer);
}


static int request_socket_write(request_t* request, const char* buf, int len) {
  return request->is_ssl ? mbedtls_ssl_write(&request->ssl_context, buf, len) : write(request->socket, buf, len);
}

static int request_socket_read(request_t* request, char* buf, int len) {
  return request->is_ssl ? mbedtls_ssl_read(&request->ssl_context, buf, len) : read(request->socket, buf, len);
}


static int check_request(request_t* request) {
  switch (request->state) {
    case REQUEST_STATE_INIT:
      char err[1024] = {0};
      if (request->is_ssl) {
        int status;
        char port[10];
        snprintf(port, sizeof(port), "%d", (int)request->port);
        // https://gist.github.com/Barakat/675c041fd94435b270a25b5881987a30
        if ((status = mbedtls_ssl_setup(&request->ssl_context, &ssl_config)) != 0) {
          mbedtls_snprintf(1, err, sizeof(err), status, "can't set up ssl for %s: %d", request->hostname, status); goto cleanup;
        }
        mbedtls_net_set_nonblock(&request->net_context);
        mbedtls_ssl_set_bio(&request->ssl_context, &request->net_context, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);
        if ((status = mbedtls_net_connect(&request->net_context, request->hostname, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
          mbedtls_snprintf(1, err, sizeof(err), status, "can't connect to hostname %s", request->hostname); goto cleanup;
        } else if ((status = mbedtls_ssl_set_hostname(&request->ssl_context, request->hostname)) != 0) {
          mbedtls_snprintf(1, err, sizeof(err), status, "can't set hostname %s", request->hostname); goto cleanup;
        } else if ((status = mbedtls_ssl_handshake(&request->ssl_context)) != 0) {
          mbedtls_snprintf(1, err, sizeof(err), status, "can't handshake with %s", request->hostname); goto cleanup;
        } else if (((status = mbedtls_ssl_get_verify_result(&request->ssl_context)) != 0) && !no_verify_ssl) {
          mbedtls_snprintf(1, err, sizeof(err), status, "can't verify result for %s", request->hostname); goto cleanup;
        }
      } else {
        struct hostent *host = gethostbyname(request->hostname);
        struct sockaddr_in dest_addr = {0};
        if (!host) {
          snprintf(err, sizeof(err), "can't resolve hostname %s", request->hostname);
          goto cleanup;
        }
        int s = socket(AF_INET, SOCK_STREAM, 0);
        #ifdef _WIN32
          DWORD timeout = 5 * 1000;
          setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
        #else
          struct timeval tv;
          tv.tv_sec = 5;
          tv.tv_usec = 0;
          setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        #endif
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(request->port);
        dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
        const char* ip = inet_ntoa(dest_addr.sin_addr);
        if (connect(s, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1 ) {
          close(s);
          snprintf(err, sizeof(err), "can't connect to host %s [%s] on port %d", request->hostname, ip, request->port);
          goto cleanup;
        }
        request->socket = s;
      }
      cleanup:
        if (err[0]) {
          request->state = REQUEST_STATE_ERROR;
          strncpy(request->chunk, err, sizeof(request->chunk));
          request->chunk_length = strlen(err);
        } else {
          request->state = REQUEST_STATE_SEND_HEADERS;
        }
    break;
    case REQUEST_STATE_SEND_HEADERS:
    case REQUEST_STATE_SEND_BODY:
      int bytes_written = request_socket_write(request, request->chunk, request->chunk_length);
      if (bytes_written < 0) {
        request->state = REQUEST_STATE_ERROR;
        return 0;
      }
      if (bytes_written == request->chunk_length) {
        request->chunk_length = 0;
        if (request->state == REQUEST_STATE_SEND_HEADERS) {
          if (!request->is_get)
            request->state = REQUEST_STATE_SEND_BODY;
          else
            request->state = REQUEST_STATE_RECV_HEADERS;
        }
      } else {
        memmove(&request->chunk[bytes_written], request->chunk, request->chunk_length - bytes_written);
        request->chunk_length -= bytes_written;
      }
    break;
    case REQUEST_STATE_RECV_HEADERS:
      int bytes_read = request_socket_read(request, &request->chunk[request->chunk_length], sizeof(request->chunk) - request->chunk_length);
      if (bytes_read < 0) {
        request->state = REQUEST_STATE_ERROR;
        return 0;
      }
      if (bytes_read > 0) {
        request->chunk_length += bytes_read;
        const char* boundary = strstr(request->chunk, "\r\n\r\n");
        if (boundary)
          request->state = REQUEST_STATE_RECV_PROCESS_HEADERS;
      }
    break;
    case REQUEST_STATE_RECV_BODY:
      if (sizeof(request->chunk) - request->chunk_length > 0) {
        int bytes_read = request_socket_read(request, &request->chunk[request->chunk_length], sizeof(request->chunk) - request->chunk_length);
        if (bytes_read < 0) {
          request->state = REQUEST_STATE_ERROR;
          return 0;
        } else if (bytes_read > 0) {
          request->chunk_length += bytes_read;
          request->body_transmitted += bytes_read;
        }
      }
    break;
    case REQUEST_STATE_RECV_PROCESS_HEADERS: break;
  }
  return -1;
}

static void* www_request_thread_callback(void* data) {
  while (1) {
    lock_mutex(www_mutex);
    int should_exit = request_queue == NULL;
    if (should_exit) {
      www_thread = NULL;
      unlock_mutex(www_mutex);
      break;
    }
    request_t* request = request_queue;
    while (request) {
      check_request(request);
      request = request->next;
    }
    unlock_mutex(www_mutex);
    sleep_in_miliseconds(1);
  }
  return NULL;
}

static int ssl_initialized;
static int f_www_ssl(lua_State* L) {
  char err[1024] = {0};
  const char* type = luaL_checkstring(L, 1);
  int status;
  if (ssl_initialized) {
    mbedtls_ssl_config_free(&ssl_config);
    mbedtls_ctr_drbg_free(&drbg_context);
    mbedtls_entropy_free(&entropy_context);
    mbedtls_x509_crt_free(&x509_certificate);
    ssl_initialized = 0;
  }
  if (strcmp(type, "none") == 0)
    return 0;
  mbedtls_x509_crt_init(&x509_certificate);
  mbedtls_entropy_init(&entropy_context);
  mbedtls_ctr_drbg_init(&drbg_context);
  if ((status = mbedtls_ctr_drbg_seed(&drbg_context, mbedtls_entropy_func, &entropy_context, NULL, 0)) != 0) {
    mbedtls_snprintf(1, err, sizeof(err), status, "failed to setup mbedtls_x509");
    return luaL_error(L, "%s", err);
  }
  mbedtls_ssl_config_init(&ssl_config);
  status = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  mbedtls_ssl_conf_max_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_authmode(&ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &drbg_context);
  mbedtls_ssl_conf_read_timeout(&ssl_config, 5000);
  #if defined(MBEDTLS_DEBUG_C)
  /*if (print_trace) {
    mbedtls_debug_set_threshold(5);
    //mbedtls_ssl_conf_dbg(&ssl_config, lpm_tls_debug, NULL);
  }*/
  #endif
  ssl_initialized = 1;
  if (strcmp(type, "noverify") == 0) {
    no_verify_ssl = 1;
    mbedtls_ssl_conf_authmode(&ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
  } else {
    const char* path = luaL_checkstring(L, 2);
    if (strcmp(type, "system") == 0) {
      #if _WIN32
        FILE* file = lua_fopen(L, path, "wb");
        if (!file)
          return luaL_error(L, "can't open cert store %s for writing: %s", path, strerror(errno));
        HCERTSTORE hSystemStore = CertOpenSystemStore(0, TEXT("ROOT"));
        if (!hSystemStore) {
          fclose(file);
          return luaL_error(L, "error getting system certificate store");
        }
        PCCERT_CONTEXT pCertContext = NULL;
        while (1) {
          pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext);
          if (!pCertContext)
            break;
          BYTE keyUsage[2];
          if (pCertContext->dwCertEncodingType & X509_ASN_ENCODING && (CertGetIntendedKeyUsage(pCertContext->dwCertEncodingType, pCertContext->pCertInfo, keyUsage, sizeof(keyUsage)) && (keyUsage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))) {
            DWORD size = 0;
            CryptBinaryToString(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &size);
            char* buffer = malloc(size);
            CryptBinaryToString(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, buffer, &size);
            fwrite(buffer, sizeof(char), size, file);
            free(buffer);
          }
        }
        fclose(file);
        CertCloseStore(hSystemStore, 0);
      #else
        const char* paths[] = {
          "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
          "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
          "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
          "/etc/pki/tls/cacert.pem",                           // OpenELEC
          "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
          "/etc/ssl/cert.pem",                                 // Alpine Linux (and Mac OSX)
          "/etc/ssl/certs",                                    // SLES10/SLES11, https://golang.org/issue/12139
          "/system/etc/security/cacerts",                      // Android
          "/usr/local/share/certs",                            // FreeBSD
          "/etc/pki/tls/certs",                                // Fedora/RHEL
          "/etc/openssl/certs",                                // NetBSD
          "/var/ssl/certs",                                    // AIX
          NULL
        };
        for (int i = 0; paths[i]; ++i) {
          struct stat s;
          if (stat(paths[i], &s) == 0 && S_ISREG(s.st_mode)) {
            path = paths[i];
            break;
          }
        }
      #endif
    }
    if ((status = mbedtls_x509_crt_parse_file(&x509_certificate, path)) != 0) {
      mbedtls_snprintf(1, err, sizeof(err), status, "mbedtls_x509_crt_parse_file failed to parse CA certificate %s", path);
      return luaL_error(L, "%s", err);
    }
    mbedtls_ssl_conf_ca_chain(&ssl_config, &x509_certificate, NULL);
  }
  return 0;
}


static int f_www_gc(lua_State* L) {
  lock_mutex(www_mutex);
  request_t* request = request_queue;
  while (request) {
    request_t* next = request->next;
    request_complete(request);
    request = next;
  }
  request_queue = NULL;
  unlock_mutex(www_mutex);
  if (www_thread)
    join_thread(www_thread);
  free_mutex(www_mutex);
  lua_pushcfunction(L, f_www_ssl);
  lua_pushliteral(L, "none");
  lua_call(L, 1, 0);
}


static luaL_Reg www_api[] = {
  { "request",  f_www_request },
  // { "get",      f_www_get     },
  { "ssl",      f_www_ssl     },
  { "__gc",     f_www_gc },
  { NULL, NULL }
};


#ifndef WWW_STANDALONE
int luaopen_lite_xl_www(lua_State* L, void* XL) {
  lite_xl_plugin_init(XL);
#else
int luaopen_www(lua_State* L) {
#endif
  lua_pushcfunction(L, f_www_ssl);
  lua_pushliteral(L, "system");
#ifndef WWW_STANDALONE
  lua_getglobal(L, "USERDIR");
#else
  lua_pushliteral(L, "/tmp");
#endif
  lua_pushliteral(L, "/ssl.certs");
  lua_concat(L, 2);
  lua_call(L, 2, 0);
  luaL_newlib(L, www_api);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  www_mutex = new_mutex();
  return 1;
}


