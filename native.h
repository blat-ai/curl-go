#ifndef CURL_GO_NATIVE_H
#define CURL_GO_NATIVE_H
#include <stdint.h>
#include <stdlib.h>
#include "internal/include/curl/curl.h"
#include "internal/include/curl/multi.h"
#include "internal/include/curl/websockets.h"
int cg_load(const char *path, char *err, size_t len);
const char *cg_version(void);
const char *cg_strerror(int code);
CURL *cg_easy_init(void);
CURL *cg_easy_duplicate(CURL *easy);
void cg_easy_cleanup(CURL *easy);
void cg_easy_reset(CURL *easy);
int cg_setopt_long(CURL *easy, int opt, int64_t value);
int cg_setopt_off(CURL *easy, int opt, int64_t value);
int cg_setopt_ptr(CURL *easy, int opt, void *value);
int cg_setopt_blob(CURL *easy, int opt, void *data, size_t len);
int cg_impersonate(CURL *easy, const char *target, int headers);
struct curl_slist *cg_slist_append(struct curl_slist *list, const char *s);
void cg_slist_free(struct curl_slist *list);
int cg_getinfo_string(CURL *easy, int info, char **v);
int cg_getinfo_long(CURL *easy, int info, int64_t *v);
int cg_getinfo_off(CURL *easy, int info, int64_t *v);
int cg_getinfo_double(CURL *easy, int info, double *v);
int cg_getinfo_ptr(CURL *easy, int info, void **v);
int cg_getinfo_socket(CURL *easy, int info, int64_t *v);
int cg_callbacks(CURL *easy, uintptr_t id);
CURLM *cg_multi_init(void);
int cg_multi_add(CURLM *multi, CURL *easy);
int cg_multi_remove(CURLM *multi, CURL *easy);
void cg_multi_cleanup(CURLM *multi);
int cg_multi_perform(CURLM *multi, int *running);
int cg_multi_poll(CURLM *multi, int timeout);
int cg_multi_result(CURLM *multi, CURL *easy);
const char *cg_multi_strerror(int code);
int cg_upkeep(CURL *easy);
curl_mime *cg_mime_init(CURL *easy);
curl_mimepart *cg_mime_addpart(curl_mime *mime);
int cg_mime_name(curl_mimepart *part, const char *s);
int cg_mime_type(curl_mimepart *part, const char *s);
int cg_mime_filename(curl_mimepart *part, const char *s);
int cg_mime_filedata(curl_mimepart *part, const char *s);
int cg_mime_data(curl_mimepart *part, const char *s, size_t size);
void cg_mime_free(curl_mime *mime);
int cg_ws_recv(CURL *easy, void *buf, size_t len, size_t *received, struct curl_ws_frame *meta);
int cg_ws_send(CURL *easy, void *buf, size_t len, size_t *sent, curl_off_t size, unsigned int flags);
#endif
