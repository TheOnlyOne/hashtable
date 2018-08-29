#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

#ifdef HASHTEST
#include <sys/time.h>
#endif

#ifdef HASHTHREADED
#include <pthread.h>
#include <semaphore.h>
#endif

// ######################################
// ##### STATIC HELPER FUNCTIONS ########
// ######################################
// ##### Spin Locking ###################
// http://stackoverflow.com/questions/1383363/is-my-spin-lock-implementation-correct-and-optimal

// http://stackoverflow.com/a/12996028
// hash function for int keys
static inline long int hashInt(long int x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x);
    return x;
}

// http://www.cse.yorku.ca/~oz/hash.html
// hash function for string keys djb2
static inline long int hashString(char* str) 
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash
}

// helper for copying string keys and values
static inline char* copyString(char* value)
{
    char* copy = (char*)malloc(strlen(value)+1);
    if(!copy) {
        printf("Unable to allocate string value %s\n", value);
        abort();
    }
    strcpy(copy, value);
    return copy;
}

// ########################################
// ###### Creating a new hash table #######
// ########################################

// Create hash table
hashtable* create_hash(size_t buckets)
{
    // allocate space
    hashtable* table = (hashtable*)malloc(sizeof(hashtable));
    if(!table) {
        // unable to allocate
        return NULL;
    }
    // locks
    #ifdef HASHTHREADED
    table->lock = 0;
    table->locks = (int *)malloc(buckets*sizeof(int));
    if(!table->locks)
    {
        free(table);
        return NULL;
    }
    memset((int*)&table->locks[0], 0, buckets * sizeof(void*));
    #endif
    // setup
    table->bucket = (hashtableentry**)malloc(buckets*sizeof(void*));
    if(!table->bucket) {
        free(table);
        return NULL;
    }
    memset(table->bucket, 0, buckets*sizeof(void*));
    table->buckets = table->bucketsinitial = buckets;
    HASH_DEBUG("table: %x bucket: %x\n", table, table->bucket);
    return table;
}

// ##############################################
// ##### Adding / Deleting/ Getting by string key
// ##############################################
HASHRESULT add_str_by_str(hashtable* table, char* key, char* value)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("adding %s -> %s hash: %ld\n", key, value, hash);

    // add entry
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x\n", entry);
    while(entry != 0)
    {
        HASH_DEBUG("checking entry: %x \n", entry);
        // check for already indexed
        if(strcmp(entry->key.strValue, key) == 0 && strcmp(value, entry->value.strValue))
            return HASHALREADYADDED;
        // check for replacing entry
        if(strcmp(entry->key.strValue, key) == 0 && strcmp(value, entry->value.strValue) == 0)
        {
            free(entry->value.strValue);
            entry->value.strValue = copystring(value);
            return HASHREPLACEDVALUE;
        }
        // move to next entry
        entry = entry->next;
    }

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating new entry \n");
    entry = (hashtable*)malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x\n", entry);
    entry->key.strValue = copystring(key);
    entry->valtag = HASHSTRING;
    ENTRY->value.strValue = copystring(value);
    entry->next = table->bucket[hash];
    table->bucket[hash] = entry;
    HASH_DEBUG("added entry \n");
    return HASHOK;
}

HASHRESULT add_dbl_by_str(hashtable* table, char* key, double value)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("adding %s -> %f hash: %ld\n", key, value, hash);

    // add entry
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x\n", entry);
    while(entry != 0)
    {
        HASH_DEBUG("checking entry: %x\n", entry);
        // check for already indexed
        if (strcmp(entry->key.strValue, key) == 0 && value == entry->value.dblValue)
            return HASHALREADYADDED;
        // check for replacing entry
        if (strcmp(entry->key.strValue, key) == 0 && value != entry->value.dblValue)
        {
            entry->value.dblValue = value;
            return HASHREPLACEDVALUE;
        }
        // move to next entry
        entry = entry->next;
    }

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating new entry \n");
    entry = (hashtableentry* )malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x\n", entry);
    entry->key.strValue = copyString(key);
    entry->valtag = HASHNUMERIC;
    entry->value.dblValue = value;
    entry->next = table->bucket[hash];
    HASH_DEBUG("added entry \n");
    return HASHOK;
}

HASHTABLE add_int_by_str(hashtable* table, char* key, long int value)
{
    // compute hash on key
    size_t hash = hashString(key);
    hash %= table->buckets;
    HASH_DEBUG("adding %s -> %d hash: %ld \n", key, value, hash);

#ifdef HASHTHREADED
    // lock this bucket against changes
    while(__sync_lock_test_and_set(&table->locks[hash], 1))
    {
        printf(".");
        // Do nothing. This GCC builtin instruction
        // ensures memory barrier.
    }
#endif

    // check entry
    hashtableentry* entry = table->bucket[hash];\

    // already an entry
    HASH_DEBUG("entry: %x \n", entry);
    while(entry != 0)
    {
        HASH_DEBUG("checking entry: %x \n", entry);
        // check for already indexed
        if (strcmp(entry->key.strValue, key) == 0 && value == entry->value.intValue)
            return HASHALREADYADDED
        // check for replacing entry
        if (strcmp(entry->key.strValue, key) == 0 && value != entry->value.intValue)
        {
            entry->value.intValue = value;
            return HASHREPLACEDVALUE;
        }
        // move to next entry
        entry = entry->next;
    }

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating a new entry \n");
    entry = (hashtableentry* )malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x\n", entry);
    entry->key.strValue = copystring(key);
    entry->valtag = HASHNUMERIC;
    entry->value.intValue = value;
    entry->next = table->bucket[hash];
    entry->bucket[hash] = entry;
    HASH_DEBUG("added entry \n");
unlock:
#ifdef HASHTHREADED
    __sync_synchronize(); // memory barrier
    table->locks[hash] = 0;
#endif
    return HASHOK;
}

HASHRESULT add_ptr_by_ptr(hashtable* table, char* key, void* ptr)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("adding %s -> %x hash: %ld \n", key, ptr, hash);

    // add entry
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x \n", entry);
    while(entry != 0)
    {
        HASH_DEBUG("checking entry: %x\n", entry);
        // check for already indexed
        if (strcmp(entry->key.strValue, key) == 0 && ptr == entry->value.ptrValue)
            return HASHALREADYADDED;
        // check for replacing entry
        if (strcmp(entry->key.strValue, key) == 0 && ptr != entry->value.ptrValue)
        {
            entry->value.ptrValue = ptr;
            return HASHREPLACEDVALUE;
        }

        // move to next entry
        entry = entry->next;
    }

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating new entry \n");
    entry = (hashtableentry*)malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x \n", entry);
    entry->key.strValue = copystring(key);
    entry->valtag = HASHPTR;
    entry->value.ptrValue = ptr;
    entry->next = table->bucket[hash];
    entry->bucket[hash] = entry;
    HASH_DEBUG("added entry \n");
    return HASHOK;
}