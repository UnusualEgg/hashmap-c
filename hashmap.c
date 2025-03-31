#include "hashmap.h"

// #define OPENSSL_API_COMPAT 0x30000000L
#include <assert.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include "print.h"
// private
static void hm_free_val(hm_free_val_fn free_fn, void *val) {
    if (free_fn) {
        free_fn(val);
    } else {
        HM_FREE(val);
    }
}

// public
hashmap_t *hm_create(void) {
    hashmap_t *m = HM_MALLOC(sizeof(hashmap_t));
    m->len = 0;
    m->nodes = NULL;
    m->last_next_ptr = &m->nodes;
    m->free_fn = NULL;
    return m;
}

bool check_equ(uint8_t hash1[SHA256_DIGEST_LENGTH], uint8_t hash2[SHA256_DIGEST_LENGTH]) {
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (hash1[i] != hash2[i]) {
            return false;
        }
    }
    return true;
}

struct hashmap_node *hm_find(hashmap_t *hashmap, const char *key) {
    return hm_findx(hashmap, key, strlen(key));
}
struct hashmap_node *hm_findc(hashmap_t *hashmap, const char key) {
    return hm_findx(hashmap, &key, 1);
}
struct hashmap_node *hm_findi(hashmap_t *hashmap, const int key) {
    return hm_findx(hashmap, (const char *)&(key), sizeof(int));
}
// last is set if find failed. Otherwise, last is untouched
// last is node->next
struct hashmap_node *hm_findx(hashmap_t *hashmap, const void *key, size_t key_size) {
    // see if we haz it and if so then set, else malloc
    // SHA256_Update(&_ctx,key,strlen((const char*)key));
    uint8_t *hash = SHA256((const unsigned char *)key, key_size, hashmap->last_hash);
    // SHA256_Final(digest,&_ctx);

    struct hashmap_node *node = hashmap->nodes;
    struct hashmap_node **ptr = &hashmap->nodes;
    while (node) {
        if (check_equ(node->key, hash)) {
            return node;
        }
        ptr = &(node->next);
        node = node->next;
    }
    hashmap->last_next_ptr = ptr;
    return NULL;
}
void *hm_hash(hashmap_t *hashmap, const char *key) { return hm_hashx(hashmap, key, strlen(key)); }
void *hm_hashc(hashmap_t *hashmap, const char key) { return hm_hashx(hashmap, &key, 1); }
void *hm_hashi(hashmap_t *hashmap, const int key) {
    return hm_hashx(hashmap, (const char *)&key, sizeof(int));
}
void *hm_hashx(hashmap_t *hashmap, const void *key, size_t key_size) {
    SHA256((const unsigned char *)key, key_size, hashmap->last_hash);
    // so you can put this in the node parameter
    return NULL;
}

// if node is NULL then it assumes you called hm_hash
void *hm_set_ptr(hashmap_t *hashmap, struct hashmap_node *node, void *p, size_t val_size) {
    if (node) {
        // set an existing one
        HM_FREE(node->val);
        // set attributes
        node->val = p;
        node->val_size = val_size;
        return node->val;
    }
    // make a new one
    node = *(hashmap->last_next_ptr); // last was set by find
    // set attributes
    memcpy(node->key, hashmap->last_hash, SHA256_DIGEST_LENGTH);
    node->val = p;
    node->val_size = val_size;
    node->next = NULL;
    hashmap->len++;
    return node;
}
// string
void *hm_set(hashmap_t *hashmap, struct hashmap_node *node, char *val) {
    return hm_setx(hashmap, node, val, strlen(val));
}
// char
void *hm_setc(hashmap_t *hashmap, struct hashmap_node *node, char val) {
    return hm_setx(hashmap, node, &val, 1);
}
// int
void *hm_seti(hashmap_t *hashmap, struct hashmap_node *node, int val) {
    return hm_setx(hashmap, node, &val, sizeof(int));
}

void *hm_setx(hashmap_t *hashmap, struct hashmap_node *find, void *val, size_t val_size) {
    if (!find) {
        find = HM_MALLOC(sizeof(struct hashmap_node));
        if (!find) {
            fprintf(stderr, "%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        *(hashmap->last_next_ptr) = find;
        // set attributes
        memcpy(find->key, hashmap->last_hash, SHA256_DIGEST_LENGTH);
        find->val = HM_MALLOC(val_size);
        memcpy(find->val, val, val_size);
        find->val_size = val_size;
        find->next = NULL;
        hashmap->last_next_ptr = &find->next;

        hashmap->len++;
        return find->val;
    }
    if (find->val_size != val_size) {
        hm_free_val(hashmap->free_fn, find->val);
        find->val = HM_MALLOC(val_size);
    }
    memcpy(find->val, val, val_size);
    return find->val;
}

// get functions
void *hm_get(hashmap_t *hashmap, const char *key) {
    return hm_getx(hashmap, key, strlen((const char *)key));
}
void *hm_getc(hashmap_t *hashmap, const char key) { return hm_getx(hashmap, &key, 1); }
void *hm_geti(hashmap_t *hashmap, const int key) {
    return hm_getx(hashmap, (const char *)&key, sizeof(int));
}
void *hm_getx(hashmap_t *hashmap, const void *key, size_t key_size) {
    // find
    struct hashmap_node *node = hm_findx(hashmap, key, key_size);
    if (node) {
        return node->val;
    }
    return NULL;
}
// size of value
// give a ptr to a var that we'll change
void *hm_getn(hashmap_t *hashmap, const void *key, size_t key_size, size_t *size) {
    // find
    struct hashmap_node *node = hm_findx(hashmap, key, key_size);
    if (node) {
        if (size) {
            *size = node->val_size;
        }
        return node->val;
    }
    return NULL;
}

void *hm_get_fail(hashmap_t *hashmap, const char *key, size_t *size) {
    char *str = (char *)hm_getn(hashmap, key, strlen(key), size);
    if (!str) {
        fprintf(stderr, "Key \"%s\" not in dict\n", key);
        exit(EXIT_FAILURE);
    }
    return str;
}

bool hm_delete(hashmap_t *hashmap, const void *key, size_t key_size) {
    uint8_t *hash = SHA256((const unsigned char *)key, key_size, hashmap->last_hash);
    // TODO refactor
    struct hashmap_node *node = hashmap->nodes;
    struct hashmap_node *prev = NULL;
    while (node) {
        if (check_equ(node->key, hash)) {
            if (prev) {
                prev->next = node->next;
                if (!prev->next)
                    hashmap->last_next_ptr = &prev->next;
            } else {
                hashmap->nodes = node->next;
            }
            hm_free_val(hashmap->free_fn, node->val);
            HM_FREE(node);
            hashmap->len--;
            return true;
        }
        prev = node;
        node = node->next;
    }
    return false;
}
void hm_clear(hashmap_t *hashmap) {
    struct hashmap_node *node = hashmap->nodes;
    struct hashmap_node *next = hashmap->nodes;
    while (node) {
#if dbp
        printf("freeing node %p\n", node);
#endif
        next = node->next;
        hm_free_val(hashmap->free_fn, node->val);
        HM_FREE(node);
        node = next;
    }
}
void hm_free(hashmap_t *hashmap) {
    hm_clear(hashmap);
    HM_FREE(hashmap);
}

void print_val_default(struct hashmap_node *node) {
    printf("\"%c\"", *(char *)(node->val));
    if (node->val_size == sizeof(int)) {
        printf("/%d", *(int *)node->val);
    }
    printf("(%p)}", node->val);
}
void hm_debug(hashmap_t *hashmap) { hm_debugx(hashmap, print_val_default); }
void hm_debugx(hashmap_t *hashmap, hm_value_handler handler) {
    printf("hashmap {\n\tlen:%zd\n\tnodes:\n", hashmap->len);
    struct hashmap_node *node = hashmap->nodes;
    for (size_t i = 0; i < hashmap->len; i++) {
        printf("\tnode(%p){key:[", (void *)node);
        for (size_t key = 0; key < SHA256_DIGEST_LENGTH; key++) {
            printf("%02x", node->key[key]);
        }
        printf("], val:");
        handler(node);
        printf("\n");
        node = node->next;
    }
    printf("}\n");
}

hashmap_t *hm_clone(hashmap_t *m, hm_clone_val_fn clone_fn) {
    hashmap_t *new = HM_MALLOC(sizeof(hashmap_t));
    if (!new) {
        return NULL;
    }
    new->len = m->len;

    struct hashmap_node *n = m->nodes;
    struct hashmap_node *new_n = NULL;
    while (n) {
        if (!new_n) {
            new->nodes = HM_MALLOC(sizeof(struct hashmap_node));
            if (!new->nodes) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            new_n = new->nodes;
        } else {
            new_n->next = HM_MALLOC(sizeof(struct hashmap_node));
            if (!new_n->next) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            new_n = new_n->next;
        }
        memcpy(new_n->key, n->key, SHA256_DIGEST_LENGTH);

        if (clone_fn) {
            new_n->val = clone_fn(n->val);
        } else {
            new_n->val = HM_MALLOC(n->val_size);
        }
        if (!new_n->val) {
            fprintf(stderr, "%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (!clone_fn) {
            memcpy(new_n->val, n->val, n->val_size);
        }
        new_n->val_size = n->val_size;
        new_n->next = NULL;

        n = n->next;
    }
    return new;
}
