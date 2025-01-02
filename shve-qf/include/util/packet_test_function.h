//
// Created by ighxiy on 23-12-2.
//

#ifndef SHVE_CPLUS_PACKET_TEST_FUNCTION_H
#define SHVE_CPLUS_PACKET_TEST_FUNCTION_H
#include <iostream>

//for SHVE
#include "param/SHVESecretKeyParam.h"
#include "param/SHVEEncryptionParam.h"
#include "engine/SHVEPredicateEngine.h"
#include "util/RandomUtil.h"

//for QF
#include "util/HashUtil.h"
#include "QuotientFilter/qf.h"

using std::cout;
using std::endl;
using std::chrono::high_resolution_clock;

/**
 * @brief _od version of function is faster in organizing two dimension param as one dimension
 * @property SHVESecretKeyParam doesn't copy in-param: pattern. just use as pointer
*/




/**
 * @brief Use MSK to encrypt an index vector and get HVE ciphertext (c)
 * @param master_secret_key the master key
 * @param attributes a vector to encrypt
*/
char ** enc(KeyParam* master_secret_key, int* attributes, long attr_len) {
    SHVEEncryptionParam temp= SHVEEncryptionParam((SHVEMasterSecretKeyParam*)master_secret_key, attributes, attr_len);
    SHVEPredicateEngine engine(true,(KeyParam *)(&temp));
    return engine.process();
}

/**
 * @brief one dimension version of mac[][] for [char ** enc()]
 * @property faster version
*/
char * enc_od(KeyParam* master_secret_key, int* attributes, long attr_len) {
    SHVEEncryptionParam temp= SHVEEncryptionParam((SHVEMasterSecretKeyParam*)master_secret_key, attributes, attr_len);
    SHVEPredicateEngine engine(true,(KeyParam *)(&temp));
    return engine.process_od();
}


/**
 * @brief Use sk to check whether the pattern is in c.
 * @param secret_key a vector want to encrypt use master key, and store the result as a struct: secret_key
 * @param ct the vector to evaluate
*/
bool evaluate(KeyParam* secret_key, char** ct) {
    SHVEPredicateEngine engine(false, secret_key);
    return engine.evaluate(ct);
}

/**
 * @brief one dimension version of mac[][] for [bool evaluate()].
 * @property faster version
*/
bool evaluate_od(KeyParam* secret_key, char* ct) {
    SHVEPredicateEngine engine(false, secret_key);
    return engine.evaluate_od(ct);
}


/**
 * @brief Use sk to check whether the pattern is in c.\n
 * @brief procedure: use master key to encrypt a vector as a struct called secret key(hide a vector)
 * @brief --> use master key to encrypt a vector that wanting to check
 * @brief --> evaluate the enc result by secret key, does the enc result match the hidden vector?
 * @param n is vector size
*/
void SHVE_bench(long n){
    SHVEMasterSecretKeyParam MSK = SHVEMasterSecretKeyParam(n);
    int ** vectors=createNonMatchingVectors(n);

    //test area
    /*
    char input[]="test";
    //unsigned char key[16];
    //my_rand_buffer(key,16);
    char mac[16];
    unsigned char rkey[16]{};
    char *key=MSK.getMSK();
    my_aes_create_key(reinterpret_cast<unsigned char *>(key),strlen(key),rkey);
    AES_CMAC(rkey, reinterpret_cast<unsigned char *>(input), strlen(input), mac);
    */

    //test area
    /*
    cout<<"vectors to show:"<<endl;
    for(int i=0;i<n;i++)
        cout<<vectors[0][i]<<" ";
    cout<<endl;
    for(int i=0;i<n;i++)
        cout<<vectors[1][i]<<" ";
    cout<<endl;
    */

    double time_cost;
    auto time_start = high_resolution_clock::now();
    SHVESecretKeyParam sk(MSK, vectors[0], n);
    auto time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"KeyGen Time: "<<time_cost<<" ms"<<endl;

    cout<<"two dimension version-------------------"<<endl;
    time_start = high_resolution_clock::now();
    char ** mac = enc(&MSK, vectors[1], n);//change vectors[i] to show true or false result
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"Enc Time: "<<time_cost<<" ms"<<endl;

    time_start = high_resolution_clock::now();
    bool res = evaluate(&sk, mac);
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"Query Result: "<< (res?"true":"false") <<endl;
    cout<<"Query Time: "<<time_cost<<" ms"<<endl;

    cout<<"one dimension version-------------------"<<endl;
    time_start = high_resolution_clock::now();
    char * mac_od = enc_od(&MSK, vectors[0], n);//change vectors[i] to show true or false result
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"Enc Time: "<<time_cost<<" ms"<<endl;

    time_start = high_resolution_clock::now();
    bool res_od = evaluate_od(&sk, mac_od);
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"Query Result: "<< (res_od?"true":"false") <<endl;
    cout<<"Query Time: "<<time_cost<<" ms"<<endl;

    delete [] vectors[0];
    delete [] vectors[1];
    delete [] vectors;
    for(int i=0; i<n; ++i)
        delete [] mac[i];
    delete [] mac;
    delete [] mac_od;
    cout<<endl<<endl;
}



/**
 * @brief create once SHVE encrypted vector and insert once into a new QF, then search itself, always report found
 * @param n is vector size
 * @param q quotient of QF
 * @param r remainder of QF
*/
void SHVE_QF_one_round_bench(long n, int q , int r){
    //--------------------------- SHVE area
    SHVEMasterSecretKeyParam MSK = SHVEMasterSecretKeyParam(n);
    int ** vectors=createNonMatchingVectors(n);

    double time_cost;
    auto time_start = high_resolution_clock::now();
    SHVESecretKeyParam sk(MSK, vectors[0], n);
    auto time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"SHVE KeyGen Time: "<<time_cost<<" ms"<<endl;

    time_start = high_resolution_clock::now();
    char * mac_od = enc_od(&MSK, vectors[1], n);//mac_od is also n blocks of 16
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"SHVE Enc Time: "<<time_cost<<" ms"<<endl;

    std::default_random_engine randam_engine(std::random_device{}());
    std::uniform_int_distribution<> uniform_int(0,INT8_MAX);
    uint64_t shve_hash = MurmurHash64A(mac_od, 16*n, uniform_int(randam_engine));//enc result of SHVE


    //--------------------------- QF area
    struct quotient_filter qf {};
//    const uint32_t q = 28;

    time_start = high_resolution_clock::now();
    qf_init(&qf, q, r);
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF init Time: "<<time_cost<<" us"<<endl;

    time_start = high_resolution_clock::now();
    qf_insert(&qf, shve_hash);
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF insert Time: "<<time_cost<<" us"<<endl;


    time_start = high_resolution_clock::now();
    if(qf_may_contain(&qf, shve_hash)){
        cout<<"QF found result!"<<endl;
    }
    else{
        cout<<"QF not found"<<endl;
    }
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF search Time: "<<time_cost<<" us"<<endl;

    qf_destroy(&qf);
    delete [] vectors[0];
    delete [] vectors[1];
    delete [] vectors;
    delete [] mac_od;
    cout<<endl<<endl;
}


/**
 * @brief Better to test relevant small scale. Create a QF first, then create multi SHVE encrypted vectors,
 * finally insert vectors batch into QF and search themselves, always report found.
 * @param n vector size
 * @param q quotient of QF
 * @param r remainder of QF
 * @param round how many operation times
 * @param is_output whether to output qf_may_contain() result.
 */
void SHVE_QF_multi_round_bench(long n, int q , int r, int round, bool is_output){
    cout<<"[SHVE args]  n: "<< n <<", times: "<<round<<endl;
    cout<<"[QF args]  q: "<< q << ", r:"<< r <<", times: "
    <<round<<(is_output?", has output":", no output")<<", capacity is "<<(1<<q)<<endl;

    //--------------------------- QF area
    struct quotient_filter qf {};

    auto time_start = high_resolution_clock::now();
    qf_init(&qf, q, r);
    auto time_end = high_resolution_clock::now();
    double time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF init Time: "<<time_cost<<" us"<<endl;

    //--------------------------- SHVE area
    SHVEMasterSecretKeyParam MSK = SHVEMasterSecretKeyParam(n);

    cout<<"creating "<<round<<" "<< n <<"-size vectors"<<endl;
    int **vectors=new int *[round];
    for(int i=0;i<round;++i){
        vectors[i]=create_random_vectors(n);
    }

    time_start = high_resolution_clock::now();
    SHVESecretKeyParam sk(MSK, vectors[0], n);
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"SHVE KeyGen Time: "<<time_cost<<" ms"<<endl;


    char ** mac_batch = new char *[round];
    time_start = high_resolution_clock::now();
    for(int i =0;i<round;++i){
        mac_batch[i] = enc_od(&MSK, vectors[i], n);//result is also n blocks of 16
    }
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000;//ms
    cout<<"SHVE Enc "<<round<<" rounds Time: "<<time_cost<<" ms"<<endl;

    std::default_random_engine randam_engine(std::random_device{}());
    std::uniform_int_distribution<unsigned int> uniform_int(0,UINT32_MAX);
    unsigned int seed=uniform_int(randam_engine);
    uint64_t * shve_hashs = new uint64_t[round];
    for(int i =0;i<round;++i){//MurmurHash64A last param is seed, can use fixed.
        shve_hashs[i] = MurmurHash64A(mac_batch[i], 16*n, seed);//enc result of SHVE
    }

    //--------------------------- QF area
    time_start = high_resolution_clock::now();
    for(int i =0;i<round;++i){
        qf_insert(&qf, shve_hashs[i]);
    }
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF insert "<<round<<" rounds Time: "<<time_cost<<" us"<<endl;

    if(is_output){
        bool * res = new bool[round];
        time_start = high_resolution_clock::now();
        for(int i =0;i<round;++i){
            if(qf_may_contain(&qf, shve_hashs[i])){
                res[i] = true;
            }
            else{
                res[i] = false;
            }
        }
        time_end = high_resolution_clock::now();
        time_cost=double((time_end-time_start).count())/1000;//us
        cout<<"QF search (recording output) "<<round<< " rounds Time: "<<time_cost<<" us"<<endl;
        cout<<"QF search result(1=found, 0=not found):"<<endl;
        for(int i =0;i<round;++i){
            cout<<(res[i]?"1 ":"0 ");
        }
        cout<<endl;
        delete [] res;
    }
    else{//no output
        time_start = high_resolution_clock::now();
        for(int i =0;i<round;++i) {
            qf_may_contain(&qf, shve_hashs[i]);
        }
        time_end = high_resolution_clock::now();
        time_cost=double((time_end-time_start).count())/1000;//us
        cout<<"QF search (no output) "<<round<< " rounds Time: "<<time_cost<<" us"<<endl;
    }





    qf_destroy(&qf);
    for(int i =0;i<round;++i){
        delete [] vectors[i];
        delete [] mac_batch[i];
    }
    delete [] vectors;
    delete [] mac_batch;
    delete [] shve_hashs;

    cout<<endl<<endl;
}


/**
 * @brief almost the same as SHVE_QF_multi_round_bench, better for large scale test. remove some output
 * and split the test rounds into specified blocks, which declines the performance slightly(perhaps), but
 * is friendly to memory capacity. Hence, it's not testing 'round' one time, but by sections totally reach 'round' times
 * @param n vector size
 * @param q quotient of QF
 * @param r remainder of QF
 * @param round how many operation times
 * @param blocks how many blocks do you want to split the rounds, each time performing (rounds/blocks) times
 */
void SHVE_QF_multi_round_split_quiet_bench(long n, int q , int r, int round, int blocks){
    int section=round/blocks;
    cout<<"[SHVE args]  n: "<< n <<", times: "<<section*blocks<<endl;
    cout<<"[QF args]  q: "<< q << ", r:"<< r <<", times: "<<section*blocks<<", capacity is "<<(1<<q)<<endl;

    //--------------------------- QF area
    struct quotient_filter qf {};

    auto time_start = high_resolution_clock::now();
    qf_init(&qf, q, r);
    auto time_end = high_resolution_clock::now();
    double time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF init Time: "<<time_cost<<" us"<<endl;

    //--------------------------- SHVE area
    SHVEMasterSecretKeyParam MSK = SHVEMasterSecretKeyParam(n);

    double shve_keygen_time=0, shve_enc_time=0, qf_insert_time=0, qf_search_time=0;

    for(int a=0;a<blocks;++a){
        cout<<"testing round "<< a+1 <<"/"<<blocks<<endl;
        int **vectors=new int *[section];
        for(int i=0;i<section;++i){
            vectors[i]=create_random_vectors(n);
        }

        time_start = high_resolution_clock::now();
        SHVESecretKeyParam sk(MSK, vectors[0], n);
        time_end = high_resolution_clock::now();
        shve_keygen_time += double((time_end-time_start).count());

        char ** mac_batch = new char *[section];
        time_start = high_resolution_clock::now();
        for(int i =0;i<section;++i){
            mac_batch[i] = enc_od(&MSK, vectors[i], n);//result is also n blocks of 16
        }
        time_end = high_resolution_clock::now();
        shve_enc_time += double((time_end-time_start).count());

        std::default_random_engine randam_engine(std::random_device{}());
        std::uniform_int_distribution<unsigned int> uniform_int(0,UINT32_MAX);
        unsigned int seed=uniform_int(randam_engine);
        uint64_t * shve_hashs = new uint64_t[section];
        for(int i =0;i<section;++i){//MurmurHash64A last param is seed, can use fixed.
            shve_hashs[i] = MurmurHash64A(mac_batch[i], 16*n, seed);//enc result of SHVE
        }

        //--------------------------- QF area
        time_start = high_resolution_clock::now();
        for(int i =0;i<section;++i){
            qf_insert(&qf, shve_hashs[i]);
        }
        time_end = high_resolution_clock::now();
        qf_insert_time +=double((time_end-time_start).count());

        time_start = high_resolution_clock::now();
        for(int i =0;i<section;++i){
            qf_may_contain(&qf, shve_hashs[i]);
        }
        time_end = high_resolution_clock::now();
        qf_search_time += double((time_end-time_start).count());


        for(int i =0;i<section;++i){
            delete [] vectors[i];
            delete [] mac_batch[i];
        }
        delete [] vectors;
        delete [] mac_batch;
        delete [] shve_hashs;
    }
    qf_destroy(&qf);

    cout<<"SHVE KeyGen Time: "<<shve_keygen_time/1000000<<" ms"<<endl;
    cout<<"SHVE Enc Time: "<<shve_enc_time/1000000<<" ms ("<< shve_enc_time/1000000000<<" s)"<<endl;
    cout<<"QF insert Time: "<<qf_insert_time/1000<<" us ("<< qf_insert_time/1000000000<<" s)"<<endl;
    cout<<"QF search Time: "<<qf_search_time/1000<<" us ("<< qf_search_time/1000000000<<" s)"<<endl<<endl;
}


/**
 * @brief almost the same as official provided qf_bench().\n
 * @brief Has two tests. First testing random insert and search. Then testing contiguous ones(large round costs long time).\n
 * @brief Original param q=28, r=1, round=1000000. search takes a long time.\n
 * @brief Time counting for insert include generating random value and hashing time.
 * @param q quotient of QF
 * @param r remainder of QF
 * @param round how many operation times
 * @param contiguous_test whether test this or not
 */
static void QF_bench(int q, int r, int round, bool contiguous_test)
{
    struct quotient_filter qf;
    const uint32_t q_small = 16;
//    const uint32_t nlookups = 1000000;
//    int t=round/10;
    cout<<"[QF args]  q: "<< q << ", r:"<< r <<", times: "<<round<<endl;

    /* Test random inserts + lookups. */
    uint32_t ninserts = (3 * (1 << q) / 4);
//    int in=ninserts/10;
    uint32_t mask = ((1ULL << (q)) - 1);

    cout<<"Testing "<<ninserts<<" random inserts and "<<round<<" lookups"<<endl;
    auto time_start = high_resolution_clock::now();
    qf_init(&qf, q, r);
    auto time_end = high_resolution_clock::now();
    double time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF init Time: "<<time_cost<<" us"<<endl;

    std::default_random_engine randam_engine(std::random_device{}());
    std::uniform_int_distribution<unsigned long> uniform_long(0,UINT64_MAX);
//    std::uniform_int_distribution<unsigned int> uniform_int(0,UINT32_MAX);
    time_start = high_resolution_clock::now();
    while (qf.qf_entries < ninserts) {
//        qf_insert(&qf, hash_64(uniform_int(randam_engine),mask));
//        unsigned int hash=uniform_int(randam_engine);
        uint64_t hash_64=uniform_long(randam_engine);
//        qf_insert(&qf, MurmurHash64A(reinterpret_cast<void *>(&hash), 4, 0));//uint_32
        qf_insert(&qf, MurmurHash64A(reinterpret_cast<void *>(&hash_64), 8, 0));//uint_64
//        if (qf.qf_entries % in == 0) {
//            printf(".");
//            fflush(stdout);
//        }
    }
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000000000;//s
    cout<<endl<<"QF random insert Time: "<<time_cost<<" s"<<endl;

    cout<<"large round for search takes a relevant long time, please wait..."<<endl;
    time_start = high_resolution_clock::now();
    for (uint32_t i = 0; i < round; ++i) {
        //        if (qf.qf_entries % t == 0) {
//            printf(".");
//            fflush(stdout);
//        }
//        qf_may_contain(&qf, (uint64_t) uniform_int(randam_engine));
        qf_may_contain(&qf, (uint64_t) uniform_long(randam_engine));
    }
    time_end = high_resolution_clock::now();
    time_cost=double((time_end-time_start).count())/1000;//us
    cout<<"QF search Time: "<<time_cost<<" us ("<<time_cost/1000000<<")s"<<endl;

    qf_destroy(&qf);

    if(contiguous_test) {
        cout << endl << "-----------------\nThen, create a large cluster with q=16. Test random lookups" << endl;
        time_start = high_resolution_clock::now();
        qf_init(&qf, q_small, 1);
        time_end = high_resolution_clock::now();
        time_cost = double((time_end - time_start).count()) / 1000;//us
        cout << "QF init Time: " << time_cost << " us" << endl;

        cout << "Testing " << (1 << q_small) << " contiguous inserts and " << round << " lookups" << endl;

        time_start = high_resolution_clock::now();
        for (uint64_t quot = 0; quot < (1 << (q_small - 1)); ++quot) {
            uint64_t hash = quot << 1;
            qf_insert(&qf, hash);
            qf_insert(&qf, hash | 1);
//        if (quot % 2000 == 0) {
//            printf(".");
//            fflush(stdout);
//        }
        }
        time_end = high_resolution_clock::now();
        time_cost = double((time_end - time_start).count()) / 1000;//us
        cout << endl << "QF contiguous insert Time: " << time_cost << " us (" << time_cost / 1000000 << ")s" << endl;

        cout << "large round for search takes a relevant long time, please wait..." << endl;
        time_start = high_resolution_clock::now();
        for (uint32_t i = 0; i < round; ++i) {
//        qf_may_contain(&qf, (uint64_t) uniform_int(randam_engine));
            qf_may_contain(&qf, (uint64_t) uniform_long(randam_engine));
//        if (i % t == 0) {
//            printf(".");
//            fflush(stdout);
//        }
        }
        time_end = high_resolution_clock::now();
        time_cost = double((time_end - time_start).count()) / 1000000000;//s
        cout << endl << "QF search Time: " << time_cost << " s" << endl;

        qf_destroy(&qf);
    }
}
#endif //SHVE_CPLUS_PACKET_TEST_FUNCTION_H
