#if _WIN32
  #include <direct.h>
  #include <winsock2.h>
  #include <windows.h>
  #define usleep(x) Sleep((x)/1000)
#else
  #include <pthread.h>
  #include <netdb.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
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


#define MAX_REQUEST_HEADER_SIZE 4096 // This is also the max chunk size.
#define MAX_PATH_SIZE 1024
#define MAX_HOSTNAME_SIZE 256
#define MAX_PROTOCOL_SIZE 6
#define MAX_METHOD_SIZE 10
#define MAX_ERROR_SIZE 1024
#define TRANSIENT_RESPONSE_KEY "transient"

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

static mutex_t* new_mutex() {
  mutex_t* mutex = malloc(sizeof(mutex_t));
  #if _WIN32
    mutex->mutex = CreateMutex(NULL, FALSE, NULL);
  #else
    pthread_mutex_init(&mutex->mutex, NULL);
  #endif
  return mutex;
}

static void free_mutex(mutex_t* mutex) {
  #if _WIN32
    CloseHandle(mutex->mutex);
  #else
    pthread_mutex_destroy(&mutex->mutex);
  #endif
  free(mutex);
}

static void lock_mutex(mutex_t* mutex) {
  #if _WIN32
    WaitForSingleObject(mutex->mutex, INFINITE);
  #else
    pthread_mutex_lock(&mutex->mutex);
  #endif
}

static void unlock_mutex(mutex_t* mutex) {
  #if _WIN32
    ReleaseMutex(mutex->mutex);
  #else
    pthread_mutex_unlock(&mutex->mutex);
  #endif
}

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
  int is_ssl;
  int body_length;
  int body_transmitted;
  int verbose;
  time_t last_activity;
  int timeout_length;
  unsigned short port;
  request_type_e state;
  mbedtls_net_context net_context;
  mbedtls_ssl_context ssl_context;
  struct request_t* prev;
  struct request_t* next;
} request_t;


static thread_t* www_thread;
static mutex_t* www_mutex;
static request_t* request_queue;

static int lua_objlen(lua_State* L, int idx) {
  lua_len(L, idx);
  int n = lua_tointeger(L, -1);
  lua_pop(L, 1);
  return n;
}

#ifndef _WIN32
static int min(int a, int b) { return a < b ? a : b; }
static int strnicmp(const char* a, const char* b, int n) {
  for (int i = 0; i < n; ++i) {
    int difference = tolower(b[i]) - tolower(a[i]);
    if (!difference) {
      if (!a[i])
        break;
    } else
      return difference > 0 ? 1 : -1;
  }
  return 0;
}
static int stricmp(const char* a, const char* b) {
  int lena = strlen(a);
  int lenb = strlen(b);
  int cmp = strnicmp(a, b, min(lena, lenb));
  return cmp == 0 && lena != lenb ? (lena < lenb ? -1 : 1) : cmp;
}
#endif


static request_t* request_enqueue(const char* hostname, unsigned short port, const char* header, int header_length, int content_length, int is_ssl, int max_timeout, int verbose) {
  lock_mutex(www_mutex);
  request_t* request = calloc(sizeof(request_t), 1);
  request->socket = -1;
  strncpy(request->hostname, hostname, MAX_HOSTNAME_SIZE);
  strncpy(request->chunk, header, min(header_length, MAX_REQUEST_HEADER_SIZE));
  request->chunk_length = header_length;
  request->is_ssl = is_ssl;
  request->state = REQUEST_STATE_INIT;
  request->timeout_length = max_timeout;
  request->last_activity = time(NULL);
  request->body_length = content_length;
  request->port = port;
  request->verbose = verbose;
  if (is_ssl) {
    mbedtls_ssl_init(&request->ssl_context);
    mbedtls_net_init(&request->net_context);
  }
  if (request_queue) {
    request_queue->prev = request;
    request->next = request_queue;
  } else
    www_thread = create_thread(www_request_thread_callback, NULL);
  request_queue = request;
  unlock_mutex(www_mutex);
  return request;
}


static void request_complete(request_t* request) {
  lock_mutex(www_mutex);
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
  if (!request_queue) {
    if (www_thread) {
      unlock_mutex(www_mutex);
      join_thread(www_thread);
      lock_mutex(www_mutex);
    }
    www_thread = NULL;
  }
  unlock_mutex(www_mutex);
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
      switch (request->state) {
        case REQUEST_STATE_SEND_BODY: {
          int spare_room = min(sizeof(request->chunk) - request->chunk_length, request->body_length - request->body_transmitted);
          if (spare_room) {
            lua_getfield(L, 1, "body");
            int offset = 0;
            size_t chunk_length;
            int type = lua_type(L, -1);
            const char* chunk = NULL;
            switch (type) {
              case LUA_TFUNCTION: {
                lua_getfield(L, 1, "transient_chunk");
                if (lua_isnil(L, -1)) {
                  lua_pop(L, 1);
                  if (lua_pcall(L, 0, 1, 0)) {
                    lua_pushfstring(L, "error transmitting body: %s", lua_tostring(L, -1)); has_error = 1;
                    goto error;
                  }
                  lua_pushvalue(L, -1);
                  lua_setfield(L, 1, "transient_chunk");
                  lua_pushinteger(L, 0);
                  lua_setfield(L, 1, "transient_offset");
                } else {
                  lua_getfield(L, 1, "transient_offset");
                  offset = luaL_checkinteger(L, -1);
                  lua_pop(L, 1);
                }
                chunk = luaL_checklstring(L, -1, &chunk_length);
              } break;
              case LUA_TSTRING: {
                offset = request->body_transmitted;
                chunk = lua_tolstring(L, -1, &chunk_length);
              } break;
              default: {
                lua_pushfstring(L, "error transmitting body; body must be either a string or a callback function, not %s", lua_typename(L, lua_type(L, -1))); has_error = 1;
                goto error;
              }
            }
            int remaining_length = min(min(spare_room, chunk_length - offset), request->body_length - request->body_transmitted);
            if (remaining_length > 0) {
              memcpy(&request->chunk[request->chunk_length], &chunk[offset], remaining_length);
              request->chunk_length += remaining_length;
              request->body_transmitted += remaining_length;
            }
            if (type == LUA_TFUNCTION) {
              if (remaining_length) {
                lua_pushinteger(L, remaining_length + offset);
                lua_setfield(L, 1, "transient_offset");
              } else {
                lua_pushnil(L);
                lua_setfield(L, 1, "transient_chunk");
              }
            }
            lua_pop(L, 1);
          }
        } break;
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
          lua_getfield(L, request_response_table_index, TRANSIENT_RESPONSE_KEY);
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
              request->body_length = atoi(value_offset + 1);
            lua_pushlstring(L, header_start, header_name_length);
            lua_pushvalue(L, -1);
            lua_gettable(L, -3);
            int is_multiple = !lua_isnil(L, -1);
            if (!is_multiple)
              lua_pop(L, 1);
            for (value_offset = value_offset + 1; *value_offset == ' '; ++value_offset);
            lua_pushlstring(L, value_offset, header_end - value_offset);
            if (is_multiple)
              lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
            lua_rawset(L, -3);
            header_start = header_end + 2;
          }
          lua_setfield(L, -2, "headers");
          size_t header_length = header_start - request->chunk;
          memmove(request->chunk, header_start, request->chunk_length - header_length);
          request->chunk_length -= header_length;
          request->body_transmitted = 0;
          request->state = REQUEST_STATE_RECV_BODY;
          lua_pop(L, 1);
        // deliberate fallthrough.
        case REQUEST_STATE_RECV_BODY:
          if (request->chunk_length) {
            lua_getfield(L, request_response_table_index, "response");
            if (lua_type(L, -1) == LUA_TFUNCTION) {
              lua_getfield(L, request_response_table_index, TRANSIENT_RESPONSE_KEY);
              lua_pushlstring(L, request->chunk, request->chunk_length);
              if (lua_pcall(L, 2, 0, 0)) {
                lua_pushfstring(L, "error receiving body: %s", lua_tostring(L, -1)); has_error = 1;
                goto error;
              }
              request->body_transmitted += request->chunk_length;
              request->chunk_length = 0;
            } else {
              lua_pop(L, 1);
              lua_getfield(L, request_response_table_index, TRANSIENT_RESPONSE_KEY);
              luaL_getsubtable(L, -1, "body");
              lua_pushlstring(L, request->chunk, request->chunk_length);
              int n = lua_objlen(L, -2) + 1;
              lua_rawseti(L, -2, n);
              request->body_transmitted += request->chunk_length;
              request->chunk_length = 0;
              lua_pop(L, 2);
            }
          }
          if (request->body_transmitted >= request->body_length) {
            lua_getfield(L, request_response_table_index, TRANSIENT_RESPONSE_KEY);
            lua_getfield(L, -1, "body");
            int body_table_index = lua_gettop(L);
            if (lua_type(L, -1) == LUA_TTABLE) {
              int n = lua_objlen(L, -1);
              luaL_Buffer b;
              luaL_buffinit(L, &b);
              for (int i = 1; i <= n; ++i) {
                lua_rawgeti(L, body_table_index, i);
                luaL_addvalue(&b);
              }
              luaL_pushresult(&b);
              lua_setfield(L, body_table_index - 1, "body");
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
      usleep(1000);
  } while (!ctx && request->state != REQUEST_STATE_RECV_COMPLETE && request->state != REQUEST_STATE_ERROR);
  if (request->state == REQUEST_STATE_RECV_COMPLETE) {
    request_complete(request);
    lua_getfield(L, request_response_table_index, TRANSIENT_RESPONSE_KEY);
    if (ctx)
      luaL_unref(L, LUA_REGISTRYINDEX, (int)ctx);
    return 1;
  } else if (request->state == REQUEST_STATE_ERROR) {
    lua_pop(L, 1);
    lua_pushfstring(L, "error in request: %s", request->chunk);
    request_complete(request);
    return lua_error(L);
  } else {
    lua_getfield(L, request_response_table_index, "yield");
    lua_yieldk(L, 1, ctx, www_requestk);
  }
  return 0;
}


static int split_protocol_hostname_path(const char* url, char* protocol, char* hostname, char* path, unsigned short* port) {
  char* delim;
  if (!(delim = strpbrk(url, ":")) || (delim - url) > 5)
    return -1;
  strncpy(protocol, url, (delim - url));
  *port = strcmp(protocol, "https") == 0 ? 443 : 80;
  if (strncmp(&delim[1], "//", 2) != 0)
    return -1;
  delim += 3;
  char* hostname_delim;
  if ((hostname_delim = strpbrk(delim, "/"))) {
    strncpy(hostname, delim, min(MAX_HOSTNAME_SIZE, hostname_delim - delim));
    strncpy(path, hostname_delim, MAX_PATH_SIZE);
  } else {
    strncpy(hostname, delim, MAX_HOSTNAME_SIZE);
    strncpy(path, "/", MAX_PATH_SIZE);
  }
  return 0;
}


static int f_www_request(lua_State* L) {
  char method[MAX_METHOD_SIZE];
  char protocol[MAX_PROTOCOL_SIZE] = {0};
  char hostname[MAX_HOSTNAME_SIZE] = {0};
  char path[MAX_PATH_SIZE] = "/";
  char header[MAX_REQUEST_HEADER_SIZE];
  const char* version = "HTTP/1.1";

  lua_getfield(L, 1, "url");
  const char* url = luaL_checkstring(L, -1);
  unsigned short port;
  if (split_protocol_hostname_path(url, protocol, hostname, path, &port))
    return luaL_error(L, "unable to parse URL %s", url);
  if (strcmp(protocol, "http") != 0 && strcmp(protocol, "https") != 0)
    return luaL_error(L, "unrecognized protocol");
  lua_pop(L, 1);

  lua_getfield(L, 1, "verbose");
  int verbose = lua_tointeger(L, -1);
  lua_pop(L, 1);

  int max_timeout = 5;
  lua_getfield(L, 1, "timeout");
  if (!lua_isnil(L, -1))
      max_timeout = luaL_checkinteger(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, 1, "body");
  int has_body = !lua_isnil(L, -1);

  lua_getfield(L, 1, "method");
  if (!lua_isnil(L, -1))
    strncpy(method, luaL_checkstring(L, -1), sizeof(method));
  else
    strcpy(method, has_body ? "POST" : "GET");
  lua_pop(L, 1);

  int preset_content_length = strcmp(method, "GET") == 0 ? 0 : -1;
  if (lua_isstring(L, -1)) {
    size_t len;
    lua_tolstring(L, -1, &len);
    preset_content_length = len;
  }
  lua_pop(L,1);

  int header_offset = snprintf(header, sizeof(header), "%s %s %s\r\n", method, path, version);
  int has_host_header = 0;
  int has_content_length = 0;
  lua_getfield(L, 1, "headers");
  if (!lua_isnil(L, -1)) {
    lua_pushnil(L);
    while (lua_next(L, -2)) {
      if (header_offset < sizeof(header)) {
        const char* header_name = luaL_checkstring(L, -2);
        if (stricmp(header_name, "host") == 0)
          has_host_header = 1;
        else if (stricmp(header_name, "content-length") == 0) {
          has_content_length = 1;
          preset_content_length = lua_tointeger(L, -1);
        }
        switch (lua_type(L, -1)) {
          case LUA_TSTRING:
          case LUA_TNUMBER:
            header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "%s: %s\r\n", header_name, lua_tostring(L, -1));
          break;
          case LUA_TTABLE: {
            int n = lua_objlen(L, -1);
            for (int i = 1; i < n; ++i) {
              lua_rawgeti(L, -1, n);
              header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "%s: %s\r\n", header_name, lua_tostring(L, -1));
              lua_pop(L, 1);
            }
          } break;
          default:
            return luaL_error(L, "invalid header value for header %s", header_name);
        }
      }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  if (!has_host_header)
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "host: %s\r\n", hostname);
  if (!has_content_length && has_body) {
    if (preset_content_length == -1)
      return luaL_error(L, "in order to make a request with a body callback function, please specify the 'content-length' as a header.");
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "content-length: %d\r\n", preset_content_length);
  }
  header[header_offset++] = '\r';
  header[header_offset++] = '\n';
  header[header_offset] = 0;

  if (verbose == 1)
    fprintf(stderr, "%s %s://%s%s\n", method, protocol, hostname, path);

  lua_pushlightuserdata(L, request_enqueue(hostname, port, header, header_offset, preset_content_length, strcmp(protocol, "https") == 0, max_timeout, verbose));
  lua_setfield(L, 1, "request");
  lua_newtable(L);
  lua_setfield(L, 1, TRANSIENT_RESPONSE_KEY);
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
  return request->is_ssl ? mbedtls_ssl_write(&request->ssl_context, (const unsigned char*)buf, len) : write(request->socket, buf, len);
}

static int request_socket_read(request_t* request, char* buf, int len) {
  return request->is_ssl ? mbedtls_ssl_read(&request->ssl_context, (unsigned char*)buf, len) : read(request->socket, buf, len);
}


static int check_request(request_t* request) {
  switch (request->state) {
    case REQUEST_STATE_INIT: {
      char err[MAX_ERROR_SIZE] = {0};
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
        #ifndef _WIN32
          int flags = fcntl(s, F_GETFL, 0);
          fcntl(s, F_SETFL, flags | O_NONBLOCK);
        #else
          u_long mode = 1;
          ioctlsocket(s, FIONBIO, &mode);
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
    } break;
    case REQUEST_STATE_SEND_HEADERS:
    case REQUEST_STATE_SEND_BODY:
      if (request->chunk_length > 0) {
        int bytes_written = request_socket_write(request, request->chunk, request->chunk_length);
        if (bytes_written < 0) {
          request->state = REQUEST_STATE_ERROR;
          return 0;
        }
        if (bytes_written == request->chunk_length) {
          if (request->verbose == 2)
            write(fileno(stderr), request->chunk, request->chunk_length);
          request->last_activity = time(NULL);
          request->chunk_length = 0;
          if (request->state == REQUEST_STATE_SEND_HEADERS) {
            if (request->body_length != 0)
              request->state = REQUEST_STATE_SEND_BODY;
            else
              request->state = REQUEST_STATE_RECV_HEADERS;
          }
        } else if (bytes_written > 0) {
          if (request->verbose == 2)
            write(fileno(stderr), request->chunk, request->chunk_length);
          request->last_activity = time(NULL);
          memmove(&request->chunk[bytes_written], request->chunk, request->chunk_length - bytes_written);
          request->chunk_length -= bytes_written;
        }
        if (request->state == REQUEST_STATE_SEND_BODY && request->body_transmitted == request->body_length) {
          request->state = REQUEST_STATE_RECV_HEADERS;
          request->body_transmitted = 0;
        }
      }
    break;
    case REQUEST_STATE_RECV_HEADERS: {
      int bytes_read = request_socket_read(request, &request->chunk[request->chunk_length], sizeof(request->chunk) - request->chunk_length);
      if (bytes_read < 0) {
        request->state = REQUEST_STATE_ERROR;
        return 0;
      }
      if (bytes_read > 0) {
        request->last_activity = time(NULL);
        request->chunk_length += bytes_read;
        const char* boundary = strstr(request->chunk, "\r\n\r\n");
        if (boundary)
          request->state = REQUEST_STATE_RECV_PROCESS_HEADERS;
      }
    } break;
    case REQUEST_STATE_RECV_BODY:
      if (sizeof(request->chunk) - request->chunk_length > 0) {
        int bytes_read = request_socket_read(request, &request->chunk[request->chunk_length], sizeof(request->chunk) - request->chunk_length);
        if (bytes_read < 0) {
          request->state = REQUEST_STATE_ERROR;
          return 0;
        } else if (bytes_read > 0) {
          request->last_activity = time(NULL);
          request->chunk_length += bytes_read;
        }
      }
    break;
    case REQUEST_STATE_RECV_PROCESS_HEADERS: break;
    case REQUEST_STATE_RECV_COMPLETE: break;
    case REQUEST_STATE_ERROR: break;
  }
  if (time(NULL) - request->last_activity > request->timeout_length && request->state != REQUEST_STATE_ERROR && request->state != REQUEST_STATE_RECV_COMPLETE) {
    request->state = REQUEST_STATE_ERROR;
    request->chunk_length = snprintf(request->chunk, sizeof(request->chunk), "%s", "request timed out");
  }
  return -1;
}


static void* www_request_thread_callback(void* data) {
  while (1) {
    lock_mutex(www_mutex);
    int should_exit = request_queue == NULL;
    if (should_exit) {
      unlock_mutex(www_mutex);
      break;
    }
    request_t* request = request_queue;
    while (request) {
      check_request(request);
      request = request->next;
    }
    unlock_mutex(www_mutex);
    usleep(1000);
  }
  return NULL;
}


static void www_tls_debug(void *ctx, int level, const char *file, int line, const char *str) {
  fprintf(stderr, "%s:%04d: |%d| %s", file, line, level, str);
  fflush(stderr);
}


#if _WIN32
static LPCWSTR lua_toutf16(lua_State* L, const char* str) {
  if (str && str[0] == 0)
    return L"";
  int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  if (len > 0) {
    LPWSTR output = (LPWSTR) malloc(sizeof(WCHAR) * len);
    if (output) {
      len = MultiByteToWideChar(CP_UTF8, 0, str, -1, output, len);
      if (len > 0) {
        lua_pushlstring(L, (char*)output, len * 2);
        free(output);
        return (LPCWSTR)lua_tostring(L, -1);
      }
      free(output);
    }
  }
  luaL_error(L, "can't convert utf8 string");
  return NULL;
}

static FILE* lua_fopen(lua_State* L, const char* path, const char* mode) {
  FILE* file = _wfopen(lua_toutf16(L, path), lua_toutf16(L, mode));
  lua_pop(L, 2);
  return file;
}
#endif


static int f_www_ssl(lua_State* L) {
  char err[MAX_ERROR_SIZE] = {0};
  const char* type = luaL_checkstring(L, 1);
  int status;
  static int ssl_initialized;
  static mbedtls_x509_crt x509_certificate;
  static mbedtls_entropy_context entropy_context;
  static mbedtls_ctr_drbg_context drbg_context;
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
  int debug_level = luaL_checkinteger(L, 3);
  #if defined(MBEDTLS_DEBUG_C)
  if (debug_level) {
    mbedtls_debug_set_threshold(debug_level);
    mbedtls_ssl_conf_dbg(&ssl_config, www_tls_debug, NULL);
  }
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
  while (request_queue)
    request_complete(request_queue);
  free_mutex(www_mutex);
  lua_pushcfunction(L, f_www_ssl);
  lua_pushliteral(L, "none");
  lua_call(L, 1, 0);
  return 0;
}


// Core functions, `request` is the primary function, and is stateless (minus the ssl config), and makes raw requests.
static const luaL_Reg www_api[] = {
  { "__gc",     f_www_gc      },    // private, reserved cleanup function for the global ssl state and request queue
  { "request",  f_www_request },    // response = www.request({ url = string, timeout = 5, yield = 0.01, body = string|function(), method = string|"GET", headers = table|{}, response = nil|function(response, chunk)  })
  { "ssl",      f_www_ssl     },    // www.ssl(type, path|nil, debug_level)
  { NULL,       NULL          }
};


#ifndef WWW_VERSION
  #define WWW_VERSION "unknown"
#endif


#ifndef WWW_STANDALONE
int luaopen_lite_xl_www(lua_State* L, void* XL) {
  lite_xl_plugin_init(XL);
#else
int luaopen_www(lua_State* L) {
  #ifndef _WIN32
    lua_pushliteral(L, "/");
  #else
    lua_pushliteral(L, "\\");
  #endif
  lua_setglobal(L, "PATHSEP");
#endif
  luaL_newlib(L, www_api);
  lua_pushliteral(L, WWW_VERSION);
  lua_setfield(L, -2, "version");
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  const char* lua_agent_code = "\n\
    local www = ...\n\
    www.ssl('system', (USERDIR or '/tmp') .. PATHSEP .. 'ssl.certs', 0)\n\
    function www.new(default_options)\n\
      local options = { max_redirects = 10, yield = 0.01, max_timeout = 5, headers = { ['user-agent'] = 'lite-xl-www/' .. www.version } }\n\
      for k,v in pairs(default_options or {}) do options[k] = v end\n\
      return {\n\
        encode = function(value) return value end,\n\
        decode = function(value) return value end,\n\
        components = function(url)\n\
          local _, _, protocol, hostname, url = url:find('^(%w+)://([^/]+)(.*)$')\n\
          return protocol, hostname, url\n\
        end,\n\
        request = function(self, method, url, body, headers, options)\n\
          local t = { }\n\
          for k,v in pairs(self.options) do t[k] = v end\n\
          for k,v in pairs(options or {}) do t[k] = v end\n\
          for k,v in pairs(headers or {}) do t.headers[k] = v end\n\
          t.method = method\n\
          t.url = url\n\
          t.body = body\n\
          local res\n\
          while true do\n\
            local protocol, hostname, path = self.components(t.url)\n\
            if self.cookies[hostname] then\n\
              local values = {}\n\
              for k,v in pairs(self.cookies[hostname]) do table.insert(values, k .. '=' .. self.encode(v.value)) end\n\
              if not t.headers['cookie'] then t.headers['cookie'] = table.concat(values, '; ') end\n\
            end\n\
            res = www.request(t)\n\
            if res.headers['set-cookie'] then\n\
              for i,v in ipairs(type(res.headers['set-cookie']) == 'table' and res.headers['set-cookie'] or { res.headers['set-cookie'] }) do\n\
                local _, e, name, value = v:find('^([^=]+)=([^;]+)')\n\
                if not self.cookies[hostname] then self.cookies[hostname] = {} end\n\
                self.cookies[hostname][name] = { value = self.decode(value) }\n\
              end\n\
            end\n\
            if res.code >= 400 then error(res) end\n\
            if res.code < 300 then break end\n\
            t.redirected = (t.redirected or 0) + 1\n\
            if t.redirected > t.max_redirects then error('redirected ' .. t.redirected .. ', which is over the max redirect threshold') end\n\
            local location = res.headers.location\n\
            if not location then error('tried to redirect ' .. t.redirected .. ' times, but server responded with ' .. res.code .. ', and no location header.') end\n\
            t.method = 'GET'\n\
            t.body = nil\n\
            if t.headers then t.headers['content-length'] = nil end\n\
            if location:find('^/') then\n\
              protocol, hostname, path = self.components(t.url)\n\
              t.url = protocol .. '://' .. hostname .. location\n\
            else\n\
              t.url = location\n\
            end\n\
          end\n\
          return res.body, res\n\
        end,\n\
        get = function(self, url, headers, options) return self:request('GET', url, nil, headers, options) end,\n\
        post = function(self, url, body, headers, options) return self:request('POST', url, body, headers, options) end,\n\
        put = function(self, url, body, headers, options) return self:request('PUT', url, body, headers, options) end,\n\
        delete = function(self, url, body, headers, options) return self:request('DELETE', url, body, headers, options) end,\n\
        options = options,\n\
        cookies = {}\n\
      }\n\
    end\n\
  ";
  if (luaL_loadstring(L, lua_agent_code))
    return lua_error(L);
  lua_pushvalue(L, -2);
  lua_call(L, 1, 0);
  www_mutex = new_mutex();
  return 1;
}
