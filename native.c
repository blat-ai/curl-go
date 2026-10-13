#include "native.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define LIB_HANDLE HMODULE
static HMODULE open_library_utf8(const char *path) {
  int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);
  if(!n) return NULL;
  wchar_t *wide=(wchar_t *)malloc((size_t)n*sizeof(wchar_t));
  if(!wide) {SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
  if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,n)) {free(wide);return NULL;}
  HMODULE result=LoadLibraryW(wide);
  DWORD error=GetLastError();free(wide);SetLastError(error);return result;
}
#define OPEN_LIB(p) open_library_utf8(p)
#define GET_SYM(h,n) GetProcAddress(h,n)
#define CLOSE_LIB(h) FreeLibrary(h)
#else
#include <dlfcn.h>
#define LIB_HANDLE void *
#define OPEN_LIB(p) dlopen(p, RTLD_NOW | RTLD_LOCAL)
#define GET_SYM(h,n) dlsym(h,n)
#define CLOSE_LIB(h) dlclose(h)
#endif
static LIB_HANDLE library;
#define API(ret, name, args) static ret (*p_##name) args
API(CURLcode, curl_global_init, (long));
API(char *, curl_version, (void));
API(const char *, curl_easy_strerror, (CURLcode));
API(CURL *, curl_easy_init, (void));
API(CURL *, curl_easy_duphandle, (CURL *));
API(void, curl_easy_cleanup, (CURL *));
API(void, curl_easy_reset, (CURL *));
API(CURLcode, curl_easy_setopt, (CURL *, CURLoption, ...));
API(CURLcode, curl_easy_getinfo, (CURL *, CURLINFO, ...));
API(CURLcode, curl_easy_impersonate, (CURL *, const char *, int));
API(CURLcode, curl_easy_upkeep, (CURL *));
API(struct curl_slist *, curl_slist_append, (struct curl_slist *, const char *));
API(void, curl_slist_free_all, (struct curl_slist *));
API(CURLM *, curl_multi_init, (void));
API(CURLMcode, curl_multi_add_handle, (CURLM *, CURL *));
API(CURLMcode, curl_multi_remove_handle, (CURLM *, CURL *));
API(CURLMcode, curl_multi_cleanup, (CURLM *));
API(CURLMcode, curl_multi_perform, (CURLM *, int *));
API(CURLMcode, curl_multi_poll, (CURLM *, struct curl_waitfd *, unsigned int, int, int *));
API(CURLMsg *, curl_multi_info_read, (CURLM *, int *));
API(const char *, curl_multi_strerror, (CURLMcode));
API(curl_mime *, curl_mime_init, (CURL *));
API(curl_mimepart *, curl_mime_addpart, (curl_mime *));
API(CURLcode, curl_mime_name, (curl_mimepart *, const char *));
API(CURLcode, curl_mime_type, (curl_mimepart *, const char *));
API(CURLcode, curl_mime_filename, (curl_mimepart *, const char *));
API(CURLcode, curl_mime_filedata, (curl_mimepart *, const char *));
API(CURLcode, curl_mime_data, (curl_mimepart *, const char *, size_t));
API(void, curl_mime_free, (curl_mime *));
API(CURLcode, curl_ws_recv, (CURL *, void *, size_t, size_t *, const struct curl_ws_frame **));
API(CURLcode, curl_ws_send, (CURL *, const void *, size_t, size_t *, curl_off_t, unsigned int));
#define LOAD(name) do { *(void **)(&p_##name) = (void *)GET_SYM(h, #name); \
  if(!p_##name) { snprintf(err,len,"missing native symbol %s (a curl-impersonate library is required)",#name); CLOSE_LIB(h); return -1; } } while(0)
int cg_load(const char *path, char *err, size_t len) {
  if(library) return 0;
  LIB_HANDLE h = OPEN_LIB(path);
  if(!h) {
#ifdef _WIN32
    snprintf(err,len,"LoadLibrary failed (%lu)",(unsigned long)GetLastError());
#else
    snprintf(err,len,"%s",dlerror());
#endif
    return -1;
  }
  LOAD(curl_global_init); LOAD(curl_version); LOAD(curl_easy_strerror);
  LOAD(curl_easy_init); LOAD(curl_easy_duphandle); LOAD(curl_easy_cleanup); LOAD(curl_easy_reset);
  LOAD(curl_easy_setopt); LOAD(curl_easy_getinfo); LOAD(curl_easy_impersonate);
  LOAD(curl_easy_upkeep); LOAD(curl_slist_append); LOAD(curl_slist_free_all);
  LOAD(curl_multi_init); LOAD(curl_multi_add_handle); LOAD(curl_multi_remove_handle);
  LOAD(curl_multi_cleanup); LOAD(curl_multi_perform); LOAD(curl_multi_poll);
  LOAD(curl_multi_info_read); LOAD(curl_multi_strerror);
  LOAD(curl_mime_init); LOAD(curl_mime_addpart); LOAD(curl_mime_name);
  LOAD(curl_mime_type); LOAD(curl_mime_filename); LOAD(curl_mime_filedata);
  LOAD(curl_mime_data); LOAD(curl_mime_free); LOAD(curl_ws_recv); LOAD(curl_ws_send);
  int code = p_curl_global_init(CURL_GLOBAL_DEFAULT);
  if(code) { snprintf(err,len,"curl_global_init: %s",p_curl_easy_strerror(code)); CLOSE_LIB(h); return code; }
  library = h; return 0;
}
const char *cg_version(void) { return p_curl_version(); }
const char *cg_strerror(int code) { return p_curl_easy_strerror((CURLcode)code); }
CURL *cg_easy_init(void) { return p_curl_easy_init(); }
CURL *cg_easy_duplicate(CURL *e) { return p_curl_easy_duphandle(e); }
void cg_easy_cleanup(CURL *easy) { p_curl_easy_cleanup(easy); }
void cg_easy_reset(CURL *easy) { p_curl_easy_reset(easy); }
int cg_setopt_long(CURL *e,int o,int64_t v) { return p_curl_easy_setopt(e,(CURLoption)o,(long)v); }
int cg_setopt_off(CURL *e,int o,int64_t v) { return p_curl_easy_setopt(e,(CURLoption)o,(curl_off_t)v); }
int cg_setopt_ptr(CURL *e,int o,void *v) { return p_curl_easy_setopt(e,(CURLoption)o,v); }
int cg_setopt_blob(CURL *e,int o,void *v,size_t n) { struct curl_blob b={v,n,CURL_BLOB_COPY}; return p_curl_easy_setopt(e,(CURLoption)o,&b); }
int cg_impersonate(CURL *e,const char *t,int h) { return p_curl_easy_impersonate(e,t,h); }
struct curl_slist *cg_slist_append(struct curl_slist *l,const char *s) { return p_curl_slist_append(l,s); }
void cg_slist_free(struct curl_slist *l) { p_curl_slist_free_all(l); }
int cg_getinfo_string(CURL *e,int i,char **v) { return p_curl_easy_getinfo(e,(CURLINFO)i,v); }
int cg_getinfo_long(CURL *e,int i,int64_t *v) { long x=0; int r=p_curl_easy_getinfo(e,(CURLINFO)i,&x); *v=x; return r; }
int cg_getinfo_off(CURL *e,int i,int64_t *v) { curl_off_t x=0; int r=p_curl_easy_getinfo(e,(CURLINFO)i,&x); *v=x; return r; }
int cg_getinfo_double(CURL *e,int i,double *v) { return p_curl_easy_getinfo(e,(CURLINFO)i,v); }
int cg_getinfo_ptr(CURL *e,int i,void **v) { return p_curl_easy_getinfo(e,(CURLINFO)i,v); }
int cg_getinfo_socket(CURL *e,int i,int64_t *v) { curl_socket_t x=CURL_SOCKET_BAD; int r=p_curl_easy_getinfo(e,(CURLINFO)i,&x); *v=(x==CURL_SOCKET_BAD)?-1:(int64_t)x; return r; }
extern size_t goCurlWrite(uintptr_t, int, char *, size_t);
extern size_t goCurlRead(uintptr_t, char *, size_t);
extern int goCurlSeek(uintptr_t, int64_t, int);
extern int goCurlDebug(uintptr_t, int, char *, size_t);
extern int goCurlProgress(uintptr_t);
static size_t write_cb(char *p,size_t size,size_t count,void *id) { return goCurlWrite((uintptr_t)id,0,p,size*count); }
static size_t header_cb(char *p,size_t size,size_t count,void *id) { return goCurlWrite((uintptr_t)id,1,p,size*count); }
static size_t read_cb(char *p,size_t size,size_t count,void *id) { return goCurlRead((uintptr_t)id,p,size*count); }
static int seek_cb(void *id,curl_off_t offset,int origin) { return goCurlSeek((uintptr_t)id,(int64_t)offset,origin); }
static int debug_cb(CURL *e,curl_infotype type,char *p,size_t size,void *id) { (void)e; return goCurlDebug((uintptr_t)id,type,p,size); }
static int progress_cb(void *id,curl_off_t a,curl_off_t b,curl_off_t c,curl_off_t d) { (void)a; (void)b; (void)c; (void)d; return goCurlProgress((uintptr_t)id); }
int cg_callbacks(CURL *e,uintptr_t id) {
#define SET(o,v) do { int code=p_curl_easy_setopt(e,o,v); if(code) return code; } while(0)
  SET(CURLOPT_WRITEFUNCTION,write_cb); SET(CURLOPT_WRITEDATA,(void *)id);
  SET(CURLOPT_HEADERFUNCTION,header_cb); SET(CURLOPT_HEADERDATA,(void *)id);
  SET(CURLOPT_READFUNCTION,read_cb); SET(CURLOPT_READDATA,(void *)id);
  SET(CURLOPT_SEEKFUNCTION,seek_cb); SET(CURLOPT_SEEKDATA,(void *)id);
  SET(CURLOPT_DEBUGFUNCTION,debug_cb); SET(CURLOPT_DEBUGDATA,(void *)id);
  SET(CURLOPT_XFERINFOFUNCTION,progress_cb); SET(CURLOPT_XFERINFODATA,(void *)id);
  return 0;
}
CURLM *cg_multi_init(void) { return p_curl_multi_init(); }
int cg_multi_add(CURLM *m,CURL *e) { return p_curl_multi_add_handle(m,e); }
int cg_multi_remove(CURLM *m,CURL *e) { return p_curl_multi_remove_handle(m,e); }
void cg_multi_cleanup(CURLM *m) { p_curl_multi_cleanup(m); }
int cg_multi_perform(CURLM *m,int *r) { return p_curl_multi_perform(m,r); }
int cg_multi_poll(CURLM *m,int t) { return p_curl_multi_poll(m,NULL,0,t,NULL); }
int cg_multi_result(CURLM *m,CURL *e) { int n; CURLMsg *msg; while((msg=p_curl_multi_info_read(m,&n))) if(msg->msg==CURLMSG_DONE && msg->easy_handle==e) return msg->data.result; return CURLE_FAILED_INIT; }
const char *cg_multi_strerror(int c) { return p_curl_multi_strerror((CURLMcode)c); }
int cg_upkeep(CURL *e) { return p_curl_easy_upkeep(e); }
curl_mime *cg_mime_init(CURL *e) { return p_curl_mime_init(e); }
curl_mimepart *cg_mime_addpart(curl_mime *m) { return p_curl_mime_addpart(m); }
int cg_mime_name(curl_mimepart *p,const char *s) { return p_curl_mime_name(p,s); }
int cg_mime_type(curl_mimepart *p,const char *s) { return p_curl_mime_type(p,s); }
int cg_mime_filename(curl_mimepart *p,const char *s) { return p_curl_mime_filename(p,s); }
int cg_mime_filedata(curl_mimepart *p,const char *s) { return p_curl_mime_filedata(p,s); }
int cg_mime_data(curl_mimepart *p,const char *s,size_t n) { return p_curl_mime_data(p,s,n); }
void cg_mime_free(curl_mime *m) { p_curl_mime_free(m); }
int cg_ws_recv(CURL *e,void *p,size_t n,size_t *r,struct curl_ws_frame *meta) { const struct curl_ws_frame *m=NULL; int c=p_curl_ws_recv(e,p,n,r,&m); if(!c && m) *meta=*m; return c; }
int cg_ws_send(CURL *e,void *p,size_t n,size_t *s,curl_off_t z,unsigned int f) { return p_curl_ws_send(e,p,n,s,z,f); }
