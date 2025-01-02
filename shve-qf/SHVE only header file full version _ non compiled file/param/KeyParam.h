//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_KEYPARAM_H
#define SHVE_CPLUS_KEYPARAM_H

/**
 * Key parameter abstraction for encryption scheme,
 * if masterKey is true, the corresponding instance is a master key
 * of the encryption scheme.
 */

class KeyParam{
public:
    explicit KeyParam(bool is_master_key){is_master_key_=is_master_key;}
    virtual void for_check(){};
    bool is_master_key() const{return is_master_key_;}
private:
    bool is_master_key_;
};

#endif //SHVE_CPLUS_KEYPARAM_H
