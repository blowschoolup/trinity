//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_SHVEMASTERSECRETKEYPARAM_H
#define SHVE_CPLUS_SHVEMASTERSECRETKEYPARAM_H

/**
 * The master secret key class, it keeps a 128-bit array
 * and is marked as master key.
 */
//#include <cstring>
#include "param/SHVEKeyParam.h"
#include "util/NTLUtil.h"
#include "util/AESUtil.h"
class SHVEMasterSecretKeyParam: public SHVEKeyParam{
public:
    explicit SHVEMasterSecretKeyParam(long size): SHVEKeyParam(true, SHVEParam(size)){
        key_len=16;
        MSK_=getRandom(key_len-1);
    }
    ~SHVEMasterSecretKeyParam(){delete[] MSK_;}
    char * getMSK(){return MSK_;}

    /**
     * The generator parameter of msk. It includes the length of index vector.
     * As we use AES-128, the key length is fixed. (i.e. 128 bits/16 bytes).
     */
    int key_len;
private:
    char * MSK_;
};

#endif //SHVE_CPLUS_SHVEMASTERSECRETKEYPARAM_H
