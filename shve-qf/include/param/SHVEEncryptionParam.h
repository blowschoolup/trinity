//
// Created by ighxiy on 23-11-24.
//

#ifndef SHVE_CPLUS_SHVEENCRYPTIONPARAM_H
#define SHVE_CPLUS_SHVEENCRYPTIONPARAM_H

#include "SHVEKeyParam.h"
#include "SHVEMasterSecretKeyParam.h"


class SHVEEncryptionParam: public SHVEKeyParam{
public:
    SHVEEncryptionParam(SHVEMasterSecretKeyParam* master_secret_key, int* attributes, long attr_len): SHVEKeyParam(true, master_secret_key->getParam()) {
        master_secret_key_ = master_secret_key;
        attributes_ = attributes;
        attr_len_ = attr_len;
    }

    SHVEMasterSecretKeyParam* getMasterSecretKey() {return master_secret_key_;}

    int getAttributeAt(int index) {return attributes_[index];}
    long getLength() const {return attr_len_;}

private:
    SHVEMasterSecretKeyParam * master_secret_key_;
    int* attributes_;
    long attr_len_;
};

#endif //SHVE_CPLUS_SHVEENCRYPTIONPARAM_H
