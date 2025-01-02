//
// Created by ighxiy on 23-12-2.
//

#ifndef SHVE_CPLUS_HASHUTIL_H
#define SHVE_CPLUS_HASHUTIL_H

#include "util/HashUtil.h"
#include <sys/types.h>
#include <cstdlib>
#include <cstdint>

uint64_t MurmurHash64B ( const void * key, int len, unsigned int seed );
uint64_t MurmurHash64A ( const void * key, int len, unsigned int seed );

uint64_t hash_64(uint64_t key, uint64_t mask);
uint64_t hash_64i(uint64_t key, uint64_t mask);


#endif //SHVE_CPLUS_HASHUTIL_H
