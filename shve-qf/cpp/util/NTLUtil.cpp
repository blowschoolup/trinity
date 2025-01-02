//
// Created by ighxiy on 23-11-23.
//
#include "util/NTLUtil.h"

//return a new char* type, remember to manage memory outside
char * getRandom(int exp){
    NTL::ZZ res, bound;
    NTL::power(bound,2,exp);
    SetSeed(NTL::ZZ(time(nullptr)));
    RandomBnd(res, bound-1);
    int num_bytes = (exp+7) / 8;
    char *r = new char[num_bytes+1]();
    NTL::BytesFromZZ(reinterpret_cast<unsigned char *>(r), res, num_bytes);//big endian
    return r;
}
