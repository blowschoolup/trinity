//
// Created by ighxiy on 23-11-24.
//

#ifndef SHVE_CPLUS_AESBLOCKCIPHER_H
#define SHVE_CPLUS_AESBLOCKCIPHER_H
#include "param/KeyParam.h"
#include <stdexcept>

class AESBlockCipher{
public:
    AESBlockCipher(bool for_encryption, KeyParam* key){
        for_encryption_ = for_encryption;
        key_ = key;
    };

    char** processBlock(char** in, int inOff, int inLen) {
        if (key_ == nullptr) {
            throw std::logic_error("Engine not initialized.");
        } else {
            int maxLength = getInputBlockSize();
            if (inLen < maxLength)
                throw std::runtime_error("Input too small for the cipher.");
            else
                return process(in, inOff, inLen);
        }
    }

    char* processBlock_od(char* in, int inOff, int inLen) {
        if (key_ == nullptr) {
            throw std::logic_error("Engine not initialized.");
        } else {
            int maxLength = getInputBlockSize();
            if (inLen < maxLength)
                throw std::runtime_error("Input too small for the cipher.");
            else
                return process_od(in, inOff, inLen);
        }
    }

    virtual int getInputBlockSize() {return for_encryption_ ? in_bytes : out_bytes;}
    virtual int getOutputBlockSize() {return for_encryption_ ? out_bytes : in_bytes;}
    virtual char** process(char** in, int inOff, int inLen)=0;
    virtual char* process_od(char* in, int inOff, int inLen)=0;
    virtual char** process()=0;//return a new char** type, remember to manage memory outside
    virtual char* process_od()=0;
    virtual bool evaluate(char** in, int inOff, int inLen)=0;
    virtual bool evaluate_od(char* in, int inOff, int inLen)=0;
    virtual bool evaluate(char** in)=0;
    virtual bool evaluate_od(char* in)=0;
    int in_bytes = 16;
    int out_bytes = 16;
private:

protected:
    bool for_encryption_;
    KeyParam* key_;
};


#endif //SHVE_CPLUS_AESBLOCKCIPHER_H
