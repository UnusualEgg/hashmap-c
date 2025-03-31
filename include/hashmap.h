#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
// #define OPENSSL_API_COMPAT 0x30000000L
#include <openssl/sha.h>

#ifndef HM_MALLOC
#define HM_MALLOC(s) malloc(s)
#endif
#ifndef HM_FREE
#define HM_FREE(p) free(p)
#endif

typedef void (*hm_free_val_fn)(void *val);
typedef void *(*hm_clone_val_fn)(void *val);

struct hashmap_node {
    uint8_t key[SHA256_DIGEST_LENGTH];
    void *val;
    size_t val_size;
    struct hashmap_node *next;
};
typedef struct {
    size_t len;
    struct hashmap_node *nodes;
    hm_free_val_fn free_fn;

    struct hashmap_node **last;
    uint8_t last_hash[SHA256_DIGEST_LENGTH];
} hashmap_t;

// creation&deletion
hashmap_t *hm_create(void);
void hm_free(hashmap_t *hashmap);
hashmap_t *hm_clone(hashmap_t *m, hm_clone_val_fn clone_fn);

// find
#define hm_finds hm_find
struct hashmap_node *hm_find(hashmap_t *hashmap, const char *key);
struct hashmap_node *hm_findc(hashmap_t *hashmap, const char key);
struct hashmap_node *hm_findi(hashmap_t *hashmap, const int key);
struct hashmap_node *hm_findx(hashmap_t *hashmap, const void *key, size_t key_size);

// new
#define hm_hashs hm_hash
void *hm_hash(hashmap_t *hashmap, const char *key);
void *hm_hashc(hashmap_t *hashmap, const char key);
void *hm_hashi(hashmap_t *hashmap, const int key);
void *hm_hashx(hashmap_t *hashmap, const void *key, size_t key_size);

// set
#define hm_sets hm_set
// assumes you called hm_hash if node is NULL
void *hm_set(hashmap_t *hashmap, struct hashmap_node *node, char *val);
// set to pre malloc'd ptr
void *hm_set_ptr(hashmap_t *hashmap, struct hashmap_node *node, void *p, size_t val_size);
void *hm_setc(hashmap_t *hashmap, struct hashmap_node *node, char val);
void *hm_seti(hashmap_t *hashmap, struct hashmap_node *node, int val);
void *hm_setx(hashmap_t *hashmap, struct hashmap_node *find, void *val, size_t val_size);

// get
#define hm_gets hm_get
void *hm_get(hashmap_t *hashmap, const char *key);
void *hm_getc(hashmap_t *hashmap, const char key);
void *hm_geti(hashmap_t *hashmap, const int key);
void *hm_getx(hashmap_t *hashmap, const void *key, size_t key_size);
// also return size of value
void *hm_getn(hashmap_t *hashmap, const void *key, size_t key_size, size_t *size);
void *hm_get_fail(hashmap_t *hashmap, const char *key, size_t *size);

// true if deleted
bool hm_delete(hashmap_t *hashmap, const void *key, size_t key_size);

void hm_debug(hashmap_t *hashmap);
//'\n' will be printed after this is called
typedef void (*hm_value_handler)(struct hashmap_node *);
void hm_debugx(hashmap_t *hashmap, hm_value_handler handler);
