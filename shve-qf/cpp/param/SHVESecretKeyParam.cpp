//
// Created by ighxiy on 23-11-23.
//

/**
 * The secret key (sk) for a given predicate vector.
 * D0: Masked secret key
 * D1: Encrypted "0"
 * S: non-wildcard position
 */
//#include <cstring>
#include <charconv>
#include "param/SHVESecretKeyParam.h"
#include "util/AESUtil.h"
#include "util/global_param.h"

#ifdef multi_thread
    #include <omp.h>
#endif


SHVESecretKeyParam::SHVESecretKeyParam(SHVEMasterSecretKeyParam & master_secret_key, int *pattern, long pattern_len): SHVEKeyParam(false, master_secret_key.getParam()){
    key_len=-1;
    master_secret_key_ = &master_secret_key;
    pattern_= pattern;
    pattern_len_=pattern_len;

    long len=master_secret_key.getParam().getSize();
    // The parameter should contain a valid predicate vector
    if (pattern_ == nullptr) {
        throw std::invalid_argument("pattern cannot be null.");
    } else {
        // the length of predicate vector should be the same as the length of index vector
        if (pattern_len != len) {
            throw std::invalid_argument("pattern length not valid.");
        }
    }

    S_ = new int[len]();
    D0_ = new char[16]();
    D1_ = new char[16]();

    //optimize start: create key firstly to avoid the same cycle operation
    unsigned char rkey[16],K1[16],K2[16];
    char *key=master_secret_key_->getMSK();
    my_aes_create_key(reinterpret_cast<unsigned char *>(key),strlen(key),rkey);
    generate_subkey(rkey, K1, K2);
    //optimize end


//------------------------------------- below is non-parallel version
#ifndef multi_thread

         for(int i = 0; i < len; ++i) {
        if (unlikely(isStarAt(i))) {
            S_[i] = 1;   // mark as wildcard element
        } else {
            // Evaluate PRF for non-wildcard element
            char concat[11], mac[16];
            concat[0]=getPatternAt(i)+48;
            auto e=std::to_chars(concat+1,concat+10,i,10);
//                AES_CMAC(rkey,(unsigned char * )concat,(int)(e.ptr-concat),mac);
            AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e.ptr-concat),mac);
            // XoR PRF together to get a mask
            for(int j = 0; j < 16; ++j) { //mac len is 16
                D0_[j] ^= mac[j];
            }
        }
    }

#else
//------------------------------------- below is parallel version
    int i;
    int thread_num= omp_get_num_procs();
    char **bundle_D1=new char*[thread_num];
    for(int w=0;w<thread_num;++w){
        bundle_D1[w]=new char[16]();
    }

//#pragma omp parallel for default(none) num_threads(thread_num) firstprivate(len,rkey,K1,K2,S_,bundle_D1) lastprivate(bundle_D1)
#pragma omp parallel default(none) num_threads(thread_num) firstprivate(len) shared(bundle_D1,rkey,K1,K2,S_)
 {
    char *pointer = bundle_D1[omp_get_thread_num()];
#pragma omp for
    for (i = 0; i < len; ++i) {
        if (unlikely(isStarAt(i))) {
            S_[i] = 1;   // mark as wildcard element
        } else {
            // Evaluate PRF for non-wildcard element
            char concat[11], mac[16];
            concat[0] = getPatternAt(i) + 48;
            auto e = std::to_chars(concat + 1, concat + 10, i, 10);
            AES_CMAC_WITH_PRE_SUBKEY(rkey, K1, K2, (unsigned char *) concat, (int) (e.ptr - concat), mac);
            // XoR PRF together to get a mask
            for (int j = 0; j < 16; ++j) { //mac len is 16
                pointer[j] ^= mac[j];
            }
        }
    }
}
    //write parallel result back to D0_
    for(int k=0;k<thread_num;++k){
        char * pointer=bundle_D1[k];
        for(int j = 0; j < 16; ++j) { //mac len is 16
            D0_[j] ^= pointer[j];
        }
    }
    for(int l=0;l<thread_num;++l){
        delete [] bundle_D1[l];
    }
    delete [] bundle_D1;
#endif
//------------------------------------- above is parallel version

    // Randomly choose a key K
    char *K = getRandom(127);//D0_ bits len -1. K len is 16
    unsigned char zero[]="0";
    // use K to encrypt "0"
    my_aes_encrypt(zero,1,(unsigned char *)D1_,(unsigned char *)K, 16, my_aes_128_ecb, nullptr, true);
    for(int i = 0; i < 16; i++) {//D0_ len is 16
        // mask the K by above mask
        D0_[i] ^= K[i];
    }
    delete [] K;
}