//
// Created by ighxiy on 23-11-24.
//

#ifndef SHVE_CPLUS_SHVEPREDICATEENGINE_H
#define SHVE_CPLUS_SHVEPREDICATEENGINE_H

#include "PredicateOnlyAESBlockCipher.h"
#include "param/SHVEEncryptionParam.h"
#include "util/global_param.h"

#ifdef multi_thread
    #include <omp.h>
#endif

class SHVEPredicateEngine: public PredicateOnlyAESBlockCipher{

public:
    SHVEPredicateEngine(bool for_encryption, KeyParam* key): PredicateOnlyAESBlockCipher(for_encryption,key) {
        if (for_encryption_) {
            if (dynamic_cast<SHVEEncryptionParam*>(key_) == nullptr)
                throw std::invalid_argument("SHVEEncryptionParameter are required for encryption.");
        } else if(dynamic_cast<SHVESecretKeyParam*>(key_) == nullptr)
            throw std::invalid_argument("SHVESecretKeyParameter are required for decryption.");

        size_ = ((SHVEKeyParam*) key_)->getParam().getSize();
    }

    char** process() override {return processBlock(nullptr, 0, 0);}

    char* process_od() override {return processBlock_od(nullptr, 0, 0);}

    char** process(char** C, int inOff, int inLen) override {
        if (dynamic_cast<SHVESecretKeyParam*>(key_) != nullptr) {   // evaluation
            SHVESecretKeyParam* secretKey = (SHVESecretKeyParam*)key_;
            unsigned char z[16];
            memcpy(z,secretKey->getD0(),16);
            long len = secretKey->getParam().getSize();
            for(int i = 0; i < len; ++i) {
                if (!secretKey->isStar(i)) {
                    // XoR all PRF values in non-wildcard positions of the ciphertext
                    char * c = C[i];
                    // use xor to remove the mask of K
                    for (int j = 0; j < 16; j++) {//z.length is 16
                        z[j] ^= c[j];
                    }
                }
            }
            char **res = new char *[1];

            // use the recovered K' to decrypt D1
            unsigned char dest[16];
            if(my_aes_decrypt(reinterpret_cast<unsigned char *>(const_cast<char *>(secretKey->getD1())),16,
                              dest,reinterpret_cast<unsigned char *>(z),16,my_aes_128_ecb,
                              nullptr, true)==MY_AES_BAD_DATA){
                res[0]=new char[2]{'0',0};// if K' is not correct, the given pattern is not matched
                return res;
            }
            else {
                res[0]=new char[2]{'1',0};
                return res;
            }

        } else if (inLen == getInputBlockSize()) {    // encryption
            SHVEEncryptionParam* encParams = (SHVEEncryptionParam*)key_;
            if(encParams->is_master_key()) {
                // only can use the msk to encrypt
                SHVEMasterSecretKeyParam* pk = encParams->getMasterSecretKey();
                char **mac = new char *[size_];
                for(int i = 0; i < size_; ++i){
                    mac[i] = new char [16]();
                }

                //optimize start: create key firstly to avoid the same cycle operation
                unsigned char rkey[16],K1[16],K2[16];
                char *key=pk->getMSK();
                my_aes_create_key(reinterpret_cast<unsigned char *>(key),strlen(key),rkey);
                generate_subkey(rkey, K1, K2);
                //optimize end

//------------------------------------- below is non-parallel version
#ifndef multi_thread
                if(size_==1){
                    char concat[2];
                    concat[0]=encParams->getAttributeAt(0)+48;
                    concat[1]='0';
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,2,mac[0]);
                    return mac;
                }
                int rem=int(size_%2);
                int s=int(size_-1);
                for (int i = 0; i < s; ++i) {//inner has another ++i
                    // create the ciphertext as an array of PRF values
                    char concat[22];//1+10 for each
                    concat[0]=encParams->getAttributeAt(i)+48;
                    auto e1 = std::to_chars(concat+1,concat+10,i,10);
//                    AES_CMAC(rkey,(unsigned char * )concat,(int)(e.ptr-concat),mac[i]);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e1.ptr-concat),mac[i]);

                    ++i;
                    concat[11]=encParams->getAttributeAt(i)+48;
                    auto e2 = std::to_chars(concat+12,concat+21,i,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat+11,(int)(e2.ptr-concat-11),mac[i]);
                }
                if(rem){
                    char concat[11];
                    concat[0]=encParams->getAttributeAt(s)+48;
                    auto e = std::to_chars(concat+1,concat+10,s,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e.ptr-concat),mac[s]);
                }
#else
//------------------------------------- below is parallel version
                int i;
#pragma omp parallel for default(none) num_threads(omp_get_num_procs()) shared(encParams,rkey, K1, K2, mac)
                for (i = 0; i < size_; ++i) {
                    // create the ciphertext as an array of PRF values
                    char concat[11];//1+10 for each
                    concat[0] = encParams->getAttributeAt(i) + 48;
                    auto e = std::to_chars(concat + 1, concat + 10, i, 10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey, K1, K2, (unsigned char *) concat, (int) (e.ptr - concat), mac[i]);
                }
//------------------------------------- above is parallel version
#endif
                return mac;
            }
        }
        return nullptr;
    }

    char* process_od(char* C, int inOff, int inLen) override {
        if (dynamic_cast<SHVESecretKeyParam*>(key_) != nullptr) {   // evaluation
            SHVESecretKeyParam* secretKey = (SHVESecretKeyParam*)key_;
            unsigned char z[16];
            memcpy(z,secretKey->getD0(),16);
            long len = secretKey->getParam().getSize();
            for(int i = 0; i < len; ++i) {
                if (!secretKey->isStar(i)) {
                    // XoR all PRF values in non-wildcard positions of the ciphertext
                    char * c = C+i*16;
                    // use xor to remove the mask of K
                    for (int j = 0; j < 16; j++) {//z.length is 16
                        z[j] ^= c[j];
                    }
                }
            }
            // use the recovered K' to decrypt D1
            unsigned char dest[16];
            if(my_aes_decrypt(reinterpret_cast<unsigned char *>(const_cast<char *>(secretKey->getD1())),16,
                              dest,reinterpret_cast<unsigned char *>(z),16,my_aes_128_ecb,
                              nullptr, true)==MY_AES_BAD_DATA){
                return new char[2]{'0',0};// if K' is not correct, the given pattern is not matched
            }
            else {
                return new char[2]{'1',0};
            }

        } else if (inLen == getInputBlockSize()) {    // encryption
            SHVEEncryptionParam* encParams = (SHVEEncryptionParam*)key_;
            if(encParams->is_master_key()) {
                // only can use the msk to encrypt
                SHVEMasterSecretKeyParam* pk = encParams->getMasterSecretKey();
                char *mac = new char [size_*16];

                //optimize start: create key firstly to avoid the same cycle operation
                unsigned char rkey[16],K1[16],K2[16];
                char *key=pk->getMSK();
                my_aes_create_key(reinterpret_cast<unsigned char *>(key),strlen(key),rkey);
                generate_subkey(rkey, K1, K2);
                //optimize end

//------------------------------------- below is non-parallel version
#ifndef multi_thread
                if(size_==1){
                    char concat[2];
                    concat[0]=encParams->getAttributeAt(0)+48;
                    concat[1]='0';
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,2,mac);
                    return mac;
                }
                int rem=int(size_%2);
                int s=int(size_-1);
                for (int i = 0; i < s; ++i) {//inner has another ++i
                    // create the ciphertext as an array of PRF values
                    char concat[22];//1+10 for each
                    concat[0]=encParams->getAttributeAt(i)+48;
                    auto e1 = std::to_chars(concat+1,concat+10,i,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e1.ptr-concat),mac+16*i);

                    ++i;
                    concat[11]=encParams->getAttributeAt(i)+48;
                    auto e2 = std::to_chars(concat+12,concat+21,i,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat+11,(int)(e2.ptr-concat-11),mac+16*i);
                }
                if(rem){
                    char concat[11];
                    concat[0]=encParams->getAttributeAt(s)+48;
                    auto e = std::to_chars(concat+1,concat+10,s,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e.ptr-concat),mac+16*s);
                }
#else
//------------------------------------- below is parallel version
                int i;
#pragma omp parallel for default(none) num_threads(omp_get_num_procs()) shared(encParams,rkey, K1, K2, mac)
                for (i = 0; i < size_; ++i) {
                    // create the ciphertext as an array of PRF values
                    char concat[11];//1+10 for each
                    concat[0]=encParams->getAttributeAt(i)+48;
                    auto e = std::to_chars(concat+1,concat+10,i,10);
                    AES_CMAC_WITH_PRE_SUBKEY(rkey,K1,K2,(unsigned char * )concat,(int)(e.ptr-concat),mac+16*i);
                }
//------------------------------------- above is parallel version
#endif
                return mac;
            }
        }
        return nullptr;
    }

private:
    long size_;
};

#endif //SHVE_CPLUS_SHVEPREDICATEENGINE_H
