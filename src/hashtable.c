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


HASHTABLE add_dbl_by_int(hashtable* table, long int key, double value)
{
    // compute hash on key
    size_t hash = hashInt(key) % table->buckets;
    HASH_DEBUG("adding %d -> %s hash: %d\n",key,value,hash);

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
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x \n", entry);
    while(entry!=0)
	{
		HASH_DEBUG("checking entry: %x\n",entry);
		// check for already indexed
		if(entry->key.intValue==key && value==entry->value.dblValue)
			return HASHALREADYADDED;
		// check for replacing entry
		if(entry->key.intValue==key && value!=entry->value.dblValue)
		{
			entry->value.dblValue = value;
			return HASHREPLACEDVALUE;
		}
		// move to next entry
		entry = entry->next;
	}

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating a new entry \n");
    entry = (hashtableentry* )malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x\n", entry);
    entry->key.intValue = key;
    entry->valtag = HASHNUMERIC;
    entry->value.dblValue = value;
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

HASHTABLE add_str_by_int(hashtable* table, long int key, char *value)
{
    // compute hash on key
    size_t hash = hashInt(key) % table->buckets;
    HASH_DEBUG("adding %d -> %s hash: %d\n",key,value,hash);

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
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x \n", entry);
    while(entry != 0)
    {
        HASH_DEBUG("checking entry: %x\n",entry);
		// check for already indexed
		if(entry->key.intValue==key && 0==strcmp(value,entry->value.strValue))
			return HASHALREADYADDED;
		// check for replacing entry
		if(entry->key.intValue==key && 0!=strcmp(value,entry->value.strValue))
		{
			free(entry->value.strValue);
			entry->value.strValue = copystring(value);
			return HASHREPLACEDVALUE;
		}
		// move to next entry
		entry = entry->next;
    }

    // create a new entry and add at head of bucket
    HASH_DEBUG("creating a new entry \n");
    entry = (hashtableentry* )malloc(sizeof(hashtableentry));
    HASH_DEBUG("new entry: %x\n", entry);
    entry->key.intValue = key;
    entry->valtag = HASHSTRING;
    entry->value.strValue = copystring(value);
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

HASHTABLE add_int_by_int(hashtable* table, long int key, long int value)
{
    // compute hash on key
    size_t hash = hashInt(key) % table->buckets;
    HASH_DEBUG("adding %d -> %s hash: %d\n",key,value,hash);

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
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    HASH_DEBUG("entry: %x \n", entry);
    while(entry!=0)
	{
		HASH_DEBUG("checking entry: %x\n",entry);
		// check for already indexed
		if(entry->key.intValue==key && value==entry->value.intValue)
			return HASHALREADYADDED;
		// check for replacing entry
		if(entry->key.intValue==key && value!=entry->value.intValue)
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
    entry->key.intValue = key;
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

// Delete by string 
HASHRESULT del_by_str(hashtable* table, char* key)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("deleting: %s hash: %ld\n", key, hash);

    // add entry
    hashtableentry* entry = table->bucket[hash];
    hashtableentry* previous = NULL;

    // found an entry
    HASH_DEBUG("entry: %x\n", entry);
    while(entry != 0) 
    {
        HASH_DEBUG("checking entry: %x\n", entry);
        // check for already indexed 
        if (strcmp(entry->key.strValue, key) == 0)
        {
            // skip first record, or one in the chain
            if (!previous)
                table->bucket[hash] = entry->next;
            else
                previous->next = entry->next;
            
            // delete string value if needed
            if (entry->valtag == HASHSTRING)
                free(entry->value.strValue);
            free(entry->key.strValue);
            free(entry);
            return HASHDELETED;
        }
        // move to the next entry
        previous = entry;
        entry = entry->next;
    }
    return HASHNOTFOUND;
}

// delete by long int 
HASHRESULT del_by_str(hashtable* table, long int key)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("deleting: %s hash: %ld\n", key, hash);

    // add entry
    hashtableentry* entry = table->bucket[hash];
    hashtableentry* previous = NULL;

    // found an entry
    HASH_DEBUG("entry: %x\n", entry);
    while(entry != 0) 
    {
        HASH_DEBUG("checking entry: %x\n", entry);
        // check for already indexed 
        if (entry->key.intValue==key)
        {
            // skip first record, or one in the chain
            if (!previous)
                table->bucket[hash] = entry->next;
            else
                previous->next = entry->next;
            
            // delete string value if needed
            if (entry->valtag == HASHSTRING)
                free(entry->value.strValue);
            free(entry->key.strValue);
            free(entry);
            return HASHDELETED;
        }
        // move to the next entry
        previous = entry;
        entry = entry->next;
    }
    return HASHNOTFOUND;
}

// lookup str - keyed by str
HASHRESULT get_str_by_str(hashtable* table, char* key, char** value)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("fetching %s => ?? hash: %d\n", key, hash);

    // get entry
    hashtableentry* entry = table->buckets[hash];

    // already an entry
    while(entry)
    {
        // check for key
        HASH_DEBUG("found entry key: %d value: %s\n", entry->key.intValue, entry->value.strValue);
        if (strcmp(entry->key.strValue, key) == 0)
        {
            *value = entry->value.strValue;
            return HASHOK;
        }

        // move to next entry
        entry = entry->next;
    }

    // not found
    return HASHNOTFOUND;
}

// Lookup int - keyed by str
HASHRESULT get_int_by_str(hashtable* table, char* key, int* i)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("fetching %s -> ?? hash: %d\n", key, hash);

    // get entry
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    while(entry)
    {
        // check for key
        HASH_DEBUG("found entry key: %s value: %ld\n", entry->key.strValue, entry->value.intValue);
        if (strcmp(entry->key.strValue, key) == 0)
        {
            *i = entry->value.intValue;
            return HASHOK;
        }
        // move to next entry
        entry = entry->next;
    }

    // not found
    return HASHNOTFOUND;
}

// lookup dbl - keyed by str
HASHRESULT get_dbl_by_str(hashtable* table, char* key, double* val)
{
    // compute hash on key
    size_t hash = hashString(key) % table->buckets;
    HASH_DEBUG("fetching %s -> ?? hash: %d\n", key, hash);

    // get entry
    hashtableentry* entry = table->bucket[hash];

    // already an entry
    while(entry)
    {
        // check for key
        HASH_DEBUG("found entry key: %s value: %ld\n", entry->key.strValue, entry->value.dblValue);
        if (strcmp(entry->key.strValue, key) == 0)
        {
            *i = entry->value.dblValue;
            return HASHOK;
        }
        // move to next entry
        entry = entry->next;
    }

    // not found
    return HASHNOTFOUND;
}

// Lookup str - keyed by int
HASHRESULT get_str_by_int(hashtable* table, long int key, char** value)
{
	// compute hash on key
	size_t hash = hashInt(key) % table->buckets;
	HASH_DEBUG("fetching %d -> ?? hash: %d\n",key,hash);

	// get entry
	hashtableentry* entry = table->bucket[hash];
	
	// already an entry
	while(entry)
	{
		// check for key
		HASH_DEBUG("found entry key: %d value: %s\n",entry->key.intValue,entry->value.strValue);
		if(entry->key.intValue==key) {
			*value = entry->value.strValue;
			return HASHOK;
		}
		// move to next entry
		entry = entry->next;
	}
	
	// not found
	return HASHNOTFOUND;
}