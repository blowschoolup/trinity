//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_SHVESECRETKEYPARAM_H
#define SHVE_CPLUS_SHVESECRETKEYPARAM_H

/**
 * The secret key (sk) for a given predicate vector.
 * D0: Masked secret key
 * D1: Encrypted "0"
 * S: non-wildcard position
 */
//#include <cstring>
#include "SHVEKeyParam.h"
#include "SHVEMasterSecretKeyParam.h"


class SHVESecretKeyParam: public SHVEKeyParam{
public:
    /**
     * @property: SHVESecretKeyParam doesn't copy in-param: pattern. just use as pointer
    */
    explicit SHVESecretKeyParam(SHVEMasterSecretKeyParam & master_secret_key, int *pattern, long pattern_len);

    ~SHVESecretKeyParam(){
        delete [] S_;
        delete [] D0_;
        delete [] D1_;
    }

    SHVEMasterSecretKeyParam * getMasterSecretKey() {return master_secret_key_;}
    int * getPattern() {return pattern_;}
    long getPatternLen() const {return pattern_len_;}
    bool isStarAt(int index) {return getPatternAt(index) < 0;}
    int getPatternAt(int index) {return pattern_[index];}
    bool isStar(int index) {return getSAt(index) == 1;}
    const char * getD0() {return D0_;}
    const char * getD1() {return D1_;}

    int key_len;

private:
    int getSAt(int index) {return S_[index];}

    int * pattern_;
    long pattern_len_;
    SHVEMasterSecretKeyParam * master_secret_key_;

    // Tuple of sk
    char * D0_;
    char * D1_;
    int * S_;
};

#endif //SHVE_CPLUS_SHVESECRETKEYPARAM_H
