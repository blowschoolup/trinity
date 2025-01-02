//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_SHVEKEYPARAM_H
#define SHVE_CPLUS_SHVEKEYPARAM_H

#include "KeyParam.h"
#include "SHVEParam.h"

class SHVEKeyParam: public KeyParam{
public:
    SHVEKeyParam(bool is_master_key, SHVEParam param): KeyParam(is_master_key),param_(param){}
    SHVEParam getParam(){return param_;}
private:
    SHVEParam param_;
};

#endif //SHVE_CPLUS_SHVEKEYPARAM_H
