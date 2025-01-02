//
// Created by ighxiy on 23-11-24.
//
#include "util/NTLUtil.h"
#include "engine/PredicateOnlyAESBlockCipher.h"

bool PredicateOnlyAESBlockCipher::evaluate(char** in, int inOff, int inLen) {
    char** res=processBlock(in, 0, inLen);
    if(res) {
        bool r = NTL::to_int(NTL::conv<NTL::ZZ>(res[0])) == 1;
        delete[] res[0];
        delete[] res;
        return r;
    }
    throw std::runtime_error("null of result");
}

bool PredicateOnlyAESBlockCipher::evaluate_od(char* in, int inOff, int inLen) {
    char* res=processBlock_od(in, 0, inLen);
    if(res) {
        bool r = NTL::to_int(NTL::conv<NTL::ZZ>(res)) == 1;
        delete[] res;
        return r;
    }
    throw std::runtime_error("null of result");
}

bool PredicateOnlyAESBlockCipher::evaluate(char** in) {
    char** res=processBlock(in, 0, 0);
    if(res) {
        bool r = NTL::to_int(NTL::conv<NTL::ZZ>(res[0])) == 1;
        delete[] res[0];
        delete[] res;
        return r;
    }
    throw std::runtime_error("null of result");
}

bool PredicateOnlyAESBlockCipher::evaluate_od(char* in) {
    char* res=processBlock_od(in, 0, 0);
    if(res){
        bool r=NTL::to_int(NTL::conv<NTL::ZZ>(res)) == 1;
        delete [] res;
        return r;
    }
    throw std::runtime_error("null of result");
}