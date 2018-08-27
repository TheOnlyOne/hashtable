//#define HASHTHREADED 1
//#define HASHTEST 1
//#define HASHDEBUG 1

// guards! guards!
#ifndef hashtable_h
#define hashtable_h

// needed for size_t
#include <stddef.h>

#ifdef HASHDEBUG
#define HASH_DEBUG(fmt,args...) printf(fmt, ## args)
#else
#define HASH_DEBUG(fmt,args...) do {} while (0);
#endif

// resuts codes
typedef enum
{
    HASHOK,
    HASHADDED,
    HASHREPLACEDVALUE,
    HASHALREADYADDED,
    HASHDELETED,
    HASHNOTFOUND,
} HASHRESULT;

typedef enum
{
    HASHPTR,
    HASHNUMERIC,
    HASHSTRING,
} HASHVALTAG;

typedef struct hashtableEntry hashtableEntry;
struct hashtableEntry
{
    union
    {
        char *strValue;
        double dblValue;
        int intValue;
    } key;
    HASHVALTAG valtag;
    union
    {
        char *strValue;
        double dblValue;
        int intValue;
        void *ptrValue;   
    } value;
    hashtableEntry *next;
};

typedef struct hashtable hashtable;
struct hashtable
{
    hashtableEntry **bucket;        // pointer to array of buckets
    size_t buckets;
    size_t bucketsinitial;          // if we resize, may need to hash multiple items
#ifdef HASHTHREADED
    volatile int *locks;            // array of locks
    volatile int lock;              // lock for entire table
#endif
};

// Create/delete hash table
hashtable* create_hash(size_t buckets);
void* delete_hash(hashtable *table); // clean up all memory

// Add to table - keyed by string 
HASHRESULT add_str_by_str(hashtable*, char* key, char* value);
HASHRESULT add_dbl_by_str(hashtable*, char* key, double value);
HASHRESULT add_int_by_str(hashtable*, char* key, long int value);
HASHRESULT add_ptr_by_str(hashtable*, char* key, void* value);

// Delete by string
HASHRESULT del_by_str(hashtable*, char* key);

// Get by string
HASHRESULT get_str_by_str(hashtable *table, char* key, char** value);
HASHRESULT get_int_by_str(hashtable *table, char* key, int* i);
HASHRESULT get_dbl_by_str(hashtable *table, char* key, double* val);

// Add to table - keyed by int
HASHRESULT add_str_by_int(hashtable*, long int key, char* value);
HASHRESULT add_dbl_by_int(hashtable*, long int key, double value);
HASHRESULT add_int_by_int(hashtable*, long int key, long int value);
HASHRESULT add_ptr_by_int(hashtable*, long int key, void* value);

// Delete by int 
HASHRESULT del_by_int(hashtable*, long int key);

// Get by int
HASHRESULT get_str_by_int(hashtable* table, long int key, char** value);
HASHRESULT get_int_by_int(hashtable* table, long int key, int *i);
HASHRESULT get_dbl_by_int(hashtable *table, long int key, double* val);

#endif