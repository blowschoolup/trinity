//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_SHVEPARAM_H
#define SHVE_CPLUS_SHVEPARAM_H

/**
 * The scheme parameter of SHVE, it indicates the length of
 * index/predicate vector.
 */
class SHVEParam{
public:
    SHVEParam() = default;
    explicit SHVEParam(long attribute_len){attribute_len_=attribute_len;}
    long getSize() const{return attribute_len_;}
private:
    long attribute_len_;
};

#endif //SHVE_CPLUS_SHVEPARAM_H
