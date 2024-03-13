#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
//#define OPENSSL_API_COMPAT 0x30000000L
#include <openssl/sha.h>

struct hashmap_node {
    uint8_t key[SHA256_DIGEST_LENGTH];
    void* val;
    size_t val_size;
    struct hashmap_node* next;
};
typedef struct {
    size_t len;
    struct hashmap_node* nodes;

    struct hashmap_node** last;
    uint8_t last_hash[SHA256_DIGEST_LENGTH];
} hashmap_t;

//creation
hashmap_t* hm_create();
void hm_free(hashmap_t* hashmap);

//find
#define hm_finds hm_find
struct hashmap_node* hm_find(hashmap_t* hashmap,const char* key);
struct hashmap_node* hm_findc(hashmap_t* hashmap,const char key);
struct hashmap_node* hm_findi(hashmap_t* hashmap,const int key);
struct hashmap_node* hm_findx(hashmap_t* hashmap,const char* key,size_t key_size);

//new
#define hm_news hm_new
void* hm_new(hashmap_t* hashmap,const char* key);
void* hm_newc(hashmap_t* hashmap,const char key);
void* hm_newi(hashmap_t* hashmap,const int key);
void* hm_newx(hashmap_t* hashmap,const char* key,size_t key_size);

//set
#define hm_sets hm_set
void* hm_set(hashmap_t* hashmap,struct hashmap_node* node, void* val);
//set to pre malloc'd ptr
void* hm_set_ptr(hashmap_t* hashmap,struct hashmap_node* node, void* p,size_t val_size);
void* hm_setc(hashmap_t* hashmap,struct hashmap_node* node, char val);
void* hm_seti(hashmap_t* hashmap,struct hashmap_node* node, int val);
void* hm_setx(hashmap_t* hashmap,struct hashmap_node* find, void* val,size_t val_size);

//get
#define hm_gets hm_get
void* hm_get(hashmap_t* hashmap,const char* key);
void* hm_getc(hashmap_t* hashmap,const char key);
void* hm_geti(hashmap_t* hashmap,const int key);
void* hm_getx(hashmap_t* hashmap,const char* key,size_t key_size);
void* hm_getn(hashmap_t* hashmap,const char* key,size_t key_size,size_t* size);
void* hm_get_fail(hashmap_t* hashmap,const char* key,size_t* size);

//delete entry
void hm_delete(hashmap_t* hashmap,const char* key,size_t key_size);

void hm_debug(hashmap_t* hashmap);
hashmap_t* hm_clone(hashmap_t* m);


