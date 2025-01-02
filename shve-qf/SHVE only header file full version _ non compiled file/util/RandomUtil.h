//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_RANDOMUTIL_H
#define SHVE_CPLUS_RANDOMUTIL_H
#include <random>


std::default_random_engine e(std::random_device{}());
static std::uniform_int_distribution<> u(0,1);

int** createNonMatchingVectors(long size) {
    int **result=new int *[2];
    result[0]=new int [(int)size];
    result[1]=new int [(int)size];
//    for (int i = 0; i < size; ++i) {
//        result[0][i] = u(e);
//        result[1][i] = 1 - result[0][i];
//    }
    if(size==1){
        result[0][0] = u(e);
        result[1][0] = 1-result[0][0];
    }else{
        int rem=int(size%2);
        size-=1;
        for (int i = 0; i < size; i+=2) {
            result[0][i] = u(e);
            result[0][i+1] = u(e);
            result[1][i] = 1 - result[0][i];
            result[1][i+1] = 1 - result[0][i+1];
        }
        if(rem){
            result[0][size] = u(e);
            result[1][size] = 1 - result[0][size];
        }
    }
    return result;
}


#endif //SHVE_CPLUS_RANDOMUTIL_H
