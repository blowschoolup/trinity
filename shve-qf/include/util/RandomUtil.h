//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_RANDOMUTIL_H
#define SHVE_CPLUS_RANDOMUTIL_H
#include <random>

/*
 @brief: mock java version, only 0 and 1. actually support -1 as wildcard
 @return: two none matching vectors
 */
int** createNonMatchingVectors(long size) {
    std::default_random_engine randam_engine(std::random_device{}());
    std::uniform_int_distribution<> uniform_int(0,1);
    int **result=new int *[2];
    result[0]=new int [(int)size];
    result[1]=new int [(int)size];
//    for (int i = 0; i < size; ++i) {
//        result[0][i] = u(e);
//        result[1][i] = 1 - result[0][i];
//    }
    if(size==1){
        result[0][0] = uniform_int(randam_engine);
        result[1][0] = 1-result[0][0];
    }else{
        int rem=int(size%2);
        size-=1;
        for (int i = 0; i < size; i+=2) {
            result[0][i] = uniform_int(randam_engine);
            result[0][i+1] = uniform_int(randam_engine);
            result[1][i] = 1 - result[0][i];
            result[1][i+1] = 1 - result[0][i+1];
        }
        if(rem){
            result[0][size] = uniform_int(randam_engine);
            result[1][size] = 1 - result[0][size];
        }
    }
    return result;
}


/*
 @brief: create a vector contain random -1,0,1. -1 is wildcard
 */
int* create_random_vectors(long size) {
    std::default_random_engine randam_engine(std::random_device{}());
    std::uniform_int_distribution<> uniform_int(-1,1);
    int *result=new int [size];

    if(size<4){
        for (int i = 0; i < size; ++i) {
            result[i] = uniform_int(randam_engine);
        }
    }else{
        int rem=int(size%4);
        size-=3;
        for (int i = 0; i < size; i+=4) {
            result[i] = uniform_int(randam_engine);
            result[i+1] = uniform_int(randam_engine);
            result[i+2] = uniform_int(randam_engine);
            result[i+3] = uniform_int(randam_engine);
        }
        if(rem){
            int ori=size+rem;
            for (int i = size; i < ori; ++i) {
                result[i] = uniform_int(randam_engine);
            }
        }
    }
    return result;
}
#endif //SHVE_CPLUS_RANDOMUTIL_H
