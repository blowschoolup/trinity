//
// Created by ighxiy on 23-11-24.
//

#ifndef SHVE_CPLUS_PREDICATEONLYAESBLOCKCIPHER_H
#define SHVE_CPLUS_PREDICATEONLYAESBLOCKCIPHER_H

#include "AESBlockCipher.h"

class PredicateOnlyAESBlockCipher: public AESBlockCipher{
public:
    int getInputBlockSize() override {return for_encryption_ ? 0 : out_bytes;}
    int getOutputBlockSize() override {return for_encryption_ ? out_bytes : 1;}
    // The predicate only engine inputs empty message (only one possible message "True")
    char** process() override {return processBlock(nullptr, 0, 0);}
    char* process_od() override {return processBlock_od(nullptr, 0, 0);}

    bool evaluate(char** in, int inOff, int inLen) override;

    bool evaluate_od(char* in, int inOff, int inLen) override;

    bool evaluate(char** in) override;

    bool evaluate_od(char* in) override;

protected:
    PredicateOnlyAESBlockCipher(bool for_encryption, KeyParam* key): AESBlockCipher(for_encryption, key) {
        // set the input/output bytes to 0 for predicate only engine
        in_bytes = 0;
        out_bytes = 0;
    }

};


#endif //SHVE_CPLUS_PREDICATEONLYAESBLOCKCIPHER_H
