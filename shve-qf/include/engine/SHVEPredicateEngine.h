//
// Created by ighxiy on 23-11-24.
//

#ifndef SHVE_CPLUS_SHVEPREDICATEENGINE_H
#define SHVE_CPLUS_SHVEPREDICATEENGINE_H

#include "PredicateOnlyAESBlockCipher.h"

class SHVEPredicateEngine: public PredicateOnlyAESBlockCipher{

public:
    SHVEPredicateEngine(bool for_encryption, KeyParam* key);

    char** process() override {return processBlock(nullptr, 0, 0);}

    char* process_od() override {return processBlock_od(nullptr, 0, 0);}

    char** process(char** C, int inOff, int inLen) override;

    char* process_od(char* C, int inOff, int inLen) override;

private:
    long size_;
};

#endif //SHVE_CPLUS_SHVEPREDICATEENGINE_H
