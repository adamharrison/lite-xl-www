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

#ifndef WWW_VERSION
  #define WWW_VERSION "unknown"
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
#define DEFAULT_REDIRECT_FOLLOWS 10

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
    ReleaseMutex(mutex->mutex);
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
static char default_user_agent_string[] = "lite-xl-www/" WWW_VERSION;

#ifndef min
static int min(int a, int b) { return a < b ? a : b; }
#endif

static int lua_objlen(lua_State* L, int idx) {
  lua_len(L, idx);
  int n = lua_tointeger(L, -1);
  lua_pop(L, 1);
  return n;
}

#ifndef _WIN32
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

static request_t* request_enqueue(const char* hostname, unsigned short port, const char* header, int header_length, int content_length, int is_ssl, int is_get, int verbose) {
  lock_mutex(www_mutex);
  request_t* request = calloc(sizeof(request_t), 1);
  request->socket = -1;
  strncpy(request->hostname, hostname, MAX_HOSTNAME_SIZE);
  strncpy(request->chunk, header, min(header_length, MAX_REQUEST_HEADER_SIZE));
  request->chunk_length = header_length;
  request->is_ssl = is_ssl;
  request->is_get = is_get;
  request->state = REQUEST_STATE_INIT;
  request->timeout_length = MAX_TIMEOUT;
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
      time_t current_time = time(NULL);
      switch (request->state) {
        case REQUEST_STATE_SEND_BODY:
          lua_getfield(L, 1, "body");
          switch (lua_type(L, -1)) {
            case LUA_TSTRING: {
              size_t body_length;
              const char* buffer = lua_tolstring(L, -1, &body_length);
              int chunk_length = min(sizeof(request->chunk) - request->chunk_length, body_length - request->body_transmitted);
              if (chunk_length > 0) {
                memcpy(&request->chunk[request->chunk_length], &buffer[request->body_transmitted], chunk_length);
                request->chunk_length += chunk_length;
                request->body_transmitted += chunk_length;
              }
            } break;
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
              request->body_length = atoi(value_offset + 1);
            lua_pushlstring(L, header_start, header_name_length);
            for (value_offset = value_offset + 1; *value_offset == ' '; ++value_offset);
            lua_pushlstring(L, value_offset, header_end - value_offset);
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
              request->body_transmitted += request->chunk_length;
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
              int n = lua_objlen(L, -2) + 1;
              lua_rawseti(L, -2, n);
              request->body_transmitted += request->chunk_length;
              request->chunk_length = 0;
              lua_pop(L, 2);
            }
          }
          if (request->body_transmitted >= request->body_length) {
            lua_getfield(L, request_response_table_index, "response");
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
      sleep_in_miliseconds(1);
  } while (!ctx && request->state != REQUEST_STATE_RECV_COMPLETE && request->state != REQUEST_STATE_ERROR);
  if (request->state == REQUEST_STATE_RECV_COMPLETE) {
    request_complete(request);
    lua_getfield(L, request_response_table_index, "response");
    if (ctx)
      luaL_unref(L, LUA_REGISTRYINDEX, (int)ctx);
    return 1;
  } else if (request->state == REQUEST_STATE_ERROR) {
    lua_pop(L, 1);
    lua_pushfstring(L, "error in request: %s", request->chunk);
    request_complete(request);
    return lua_error(L);
  } else {
    lua_pushnumber(L, YIELD_TIMEOUT);
    lua_yieldk(L, 1, ctx, www_requestk);
  }
  return 0;
}

static int split_protocol_hostname_path(const char* url, char* protocol, char* hostname, char* path) {
  char* delim;
  if (!(delim = strpbrk(url, ":")) || (delim - url) > 5)
    return -1;
  strncpy(protocol, url, (delim - url));
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
  if (split_protocol_hostname_path(url, protocol, hostname, path))
    return luaL_error(L, "unable to parse URL %s", url);
  if (strcmp(protocol, "http") != 0 && strcmp(protocol, "https") != 0)
    return luaL_error(L, "unrecognized protocol");

  lua_pop(L, 1);
  lua_getfield(L, 1, "verbose");
  int verbose = lua_tointeger(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, 1, "body");
  int has_body = !lua_isnil(L, -1);
  int preset_content_length = -1;
  if (lua_isstring(L, -1)) {
    size_t len;
    lua_tolstring(L, -1, &len);
    preset_content_length = len;
  }
  lua_pop(L,1);
  lua_getfield(L, 1, "method");
  if (!lua_isnil(L, -1))
    strncpy(method, luaL_checkstring(L, -1), sizeof(method));
  else
    strcpy(method, has_body ? "POST" : "GET");
  lua_pop(L, 1);

  int is_get = strcmp(method, "GET") == 0;

  int header_offset = snprintf(header, sizeof(header), "%s %s %s\r\n", method, path, version);
  int has_host_header = 0;
  int has_user_agent_header = 0;
  int has_content_length = 0;
  int has_content_type = 0;
  lua_getfield(L, 1, "headers");
  if (!lua_isnil(L, -1)) {
    lua_pushnil(L);
    while (lua_next(L, -2)) {
      if (header_offset < sizeof(header)) {
        const char* header_name = luaL_checkstring(L, -2);
        if (stricmp(header_name, "user-agent") == 0)
          has_user_agent_header = 1;
        else if (stricmp(header_name, "host") == 0)
          has_host_header = 1;
        else if (stricmp(header_name, "content-length") == 0)
          has_content_length = 1;
        else if (stricmp(header_name, "content-type") == 0)
          has_content_length = 1;
        header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "%s: %s\r\n", header_name, lua_tostring(L, -1));
      }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  if (!has_host_header)
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "Host: %s\r\n", hostname);
  if (!has_user_agent_header)
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "User-Agent: %s\r\n", default_user_agent_string);
  if (!has_content_length && has_body) {
    if (preset_content_length == -1)
      return luaL_error(L, "in order to make a request with a body callback function, please specify the 'content-length' as a header.");
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "Content-Length: %d\r\n", preset_content_length);
  }
  if (has_body && !has_content_type)
    header_offset += snprintf(&header[header_offset], sizeof(header) - header_offset, "Content-Type: application/x-www-form-urlencoded\r\n");

  header[header_offset++] = '\r';
  header[header_offset++] = '\n';
  header[header_offset + 1] = 0;
  int is_ssl = strcmp(protocol, "https") == 0;
  unsigned short port = is_ssl ? 443 : 80;
  if (verbose == 1)
    fprintf(stderr, "%s %s://%s%s\n", method, protocol, hostname, path);
  request_t* request = request_enqueue(hostname, port, header, header_offset, preset_content_length, is_ssl, is_get, verbose);
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
    case REQUEST_STATE_INIT: {
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
            if (!request->is_get)
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
    sleep_in_miliseconds(1);
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

static const char* lua_toutf8(lua_State* L, LPCWSTR str) {
  int len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
  if (len > 0) {
    char* output = (char *) malloc(sizeof(char) * len);
    if (output) {
      len = WideCharToMultiByte(CP_UTF8, 0, str, -1, output, len, NULL, NULL);
      if (len) {
        lua_pushlstring(L, output, len);
        free(output);
        return lua_tostring(L, -1);
      }
      free(output);
    }
  }
  luaL_error(L, "can't convert utf16 string");
  return NULL;
}
#endif

static FILE* lua_fopen(lua_State* L, const char* path, const char* mode) {
  #ifdef _WIN32
    FILE* file = _wfopen(lua_toutf16(L, path), lua_toutf16(L, mode));
    lua_pop(L, 2);
    return file;
  #else
    return fopen(path, mode);
  #endif
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
}

// merges the first table into the second on the stack.
static void www_merge_tables(lua_State* L) {
  lua_pushnil(L);
  while (lua_next(L, -3)) {
    lua_pushvalue(L, -2);
    lua_pushvalue(L, -2);
    lua_rawset(L, -5);
    lua_pop(L, 1);
  }
}


static int f_www_agent_request(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  const char* method = luaL_checkstring(L, 2);
  int has_body = stricmp(method, "GET") != 0;
  const char* url = luaL_checkstring(L, 3);
  if (lua_gettop(L) == (has_body ? 4 : 3))
    lua_newtable(L);
  if (has_body) {
    luaL_checktype(L, 4, LUA_TSTRING);
    luaL_checktype(L, 5, LUA_TTABLE);
  } else
    luaL_checktype(L, 4, LUA_TTABLE);
  lua_getfield(L, 1, "options");
  lua_newtable(L);
  www_merge_tables(L);
  www_merge_tables(L);
  int request_parameters_index = lua_gettop(L);
  lua_pushliteral(L, "url");
  lua_pushvalue(L, 3);
  lua_rawset(L, request_parameters_index);
  lua_pushliteral(L, "method");
  lua_pushstring(L, method);
  lua_rawset(L, request_parameters_index);
  if (has_body) {
    lua_pushliteral(L, "body");
    lua_pushvalue(L, 4);
    lua_rawset(L, request_parameters_index);
  }
  lua_pushcfunction(L, f_www_request);
  lua_pushvalue(L, request_parameters_index);
  lua_call(L, 1, 1);
  // Check for redirects.
  lua_getfield(L, request_parameters_index, "redirects");
  int redirects = lua_isnil(L, -1) ? DEFAULT_REDIRECT_FOLLOWS : lua_tointeger(L, -1);
  lua_pop(L, 1);
  while (redirects > 0) {
    lua_getfield(L, -1, "code");
    int code = lua_tointeger(L, -1);
    lua_pop(L, 1);
    if (code >= 300 && code < 400) {
      lua_getfield(L, 1, "redirected");
      int redirected_count = lua_isnil(L, -1) ? lua_tointeger(L, -1) : 0;
      lua_pop(L, 1);
      if (redirected_count > redirects)
        return luaL_error(L, "redirected %d, which is over the redirect threshold of %d", redirected_count, redirects);
      lua_getfield(L, -1, "headers");
      lua_getfield(L, -1, "location");
      if (lua_isnil(L, -1))
        return luaL_error(L, "tried to redirect %d times, but server responded with 300, and no location header.", redirected_count);

      const char* redirect_url = lua_tostring(L, -1);
      if (redirect_url[0] == '/') {
        char hostname[MAX_HOSTNAME_SIZE] = {0};
        char protocol[MAX_PROTOCOL_SIZE] = {0};
        char path[MAX_PATH_SIZE] = "/";
        if (split_protocol_hostname_path(url, protocol, hostname, path))
          return luaL_error(L, "can't parse redirect url: %s", redirect_url);
        lua_pushfstring(L, "%s://%s%s", protocol, hostname, redirect_url);
        lua_replace(L, -2);
      }
      lua_setfield(L, request_parameters_index, "url");
      lua_pushnil(L);
      lua_setfield(L, request_parameters_index, "body");
      lua_pushliteral(L, "GET");
      lua_setfield(L, request_parameters_index, "method");
      lua_pop(L, 2);
      lua_pushcfunction(L, f_www_request);
      lua_pushvalue(L, request_parameters_index);
      lua_call(L, 1, 1);
    } else
      break;
  }
  // End redirect code.
  lua_getfield(L, -1, "code");
  int code = lua_tointeger(L, -1);
  lua_pop(L, 1);
  if (code >= 300)
    return lua_error(L);
  lua_getfield(L, -1, "body");
  lua_pushvalue(L, -2);
  return 2;
}

static int f_www_agent_get(lua_State* L)   {
  lua_pushliteral(L, "GET");                  lua_insert(L, 2);
  lua_pushcfunction(L, f_www_agent_request);  lua_insert(L, 1);
  lua_call(L, lua_gettop(L) - 1, 2);
  return 2;
}
static int f_www_agent_post(lua_State* L)   {
  lua_pushliteral(L, "POST");                 lua_insert(L, 2);
  lua_pushcfunction(L, f_www_agent_request);  lua_insert(L, 1);
  lua_call(L, lua_gettop(L) - 1, 2);
  return 2;
}
static int f_www_agent_put(lua_State* L)   {
  lua_pushliteral(L, "PUT");                  lua_insert(L, 2);
  lua_pushcfunction(L, f_www_agent_request);  lua_insert(L, 1);
  lua_call(L, lua_gettop(L) - 1, 2);
  return 2;
}
static int f_www_agent_delete(lua_State* L) {
  lua_pushliteral(L, "DELETE");               lua_insert(L, 2);
  lua_pushcfunction(L, f_www_agent_request);  lua_insert(L, 1);
  lua_call(L, lua_gettop(L) - 1, 2);
  return 2;
}

static int f_www_new(lua_State* L);

 // Core functions, `request` is the primary function, and is stateless (minus the ssl config), and makes raw requests.
static const luaL_Reg www_api[] = {
  { "__gc",     f_www_gc      },    // private, reserved cleanup function for the global ssl state and request queue
  { "request",  f_www_request },    // response = www.request({ url = string, body = string|function(), method = string|"GET", headers = table|{}, callback = nil|function(response, chunk), progress = function()|nil  })
  { "ssl",      f_www_ssl     },    // www.ssl(type, path|nil, debug_level)
  { "new",      f_www_new     },    // agent = www.new(options)
  { NULL,       NULL          }
};

// Utility functions, when instantiated an agent keeps a cookie store, and provides some convenience methods.
static const luaL_Reg www_agent_api[] = {
  { "request",      f_www_agent_request },    // body, response = agent:request(method, url, options|nil)
  { "get",          f_www_agent_get     },    // body, response = agent:get(url, options|nil)
  { "post",         f_www_agent_post    },    // body, response = agent:post(url, body, options|nil)
  { "put",          f_www_agent_put     },    // body, response = agent:put(url, body, options|nil)
  { "delete",       f_www_agent_delete  },    // body, response = agent:delete(url, body, options|nil)
  { NULL,           NULL                }
};

static int f_www_new(lua_State* L) {
  int arguments = lua_gettop(L);
  luaL_newlib(L, www_agent_api);
  if (arguments > 0) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_pushvalue(L, 1);
  } else {
    lua_newtable(L);
  }
  lua_setfield(L, -2, "options");
  return 1;
}

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
  lua_pushinteger(L, 0);
  lua_call(L, 3, 0);
  luaL_newlib(L, www_api);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  www_mutex = new_mutex();
  return 1;
}


