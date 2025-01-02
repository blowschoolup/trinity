#include <iostream>
#include "util/packet_test_function.h"

int main(int argc, char ** argv) {
    cout<<"Can accept 7 number argument in order as:\n"
          "n(int): the size of vectors. default 1000\n"
          "quotient(int): q for QF. default 24\n"
          "remainder(int): r for QF(larger r improve accuracy and space cost). default 1\n"
          "round(int): how many operation times. default 10000\n"
          "is_output(int): whether output search result, 0 or 1. default 0(false)\n"
          "blocks(int): how many sections want to split for large test. default 5\n"
          "contiguous_test(int): whether test contiguous QF bench, 0 or 1. default 0(false)\n"<<endl;
    long n = 1000;  // change n to test different size of vectors
    int q = 24;
    int r = 1;
    int round = 10000;
    bool is_output = false;
    int blocks = 5;
    bool contiguous_test = false;

    if(argc==8){
        char * end_ptr;
        n=strtol(argv[1],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert n failed: not a invalid number"<<endl;
            n=1000;
        }

        q=strtol(argv[2],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert q failed: not a invalid number"<<endl;
            q=24;
        }

        r=strtol(argv[3],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert r failed: not a invalid number"<<endl;
            r=1;
        }

        round=strtol(argv[4],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert round failed: not a invalid number"<<endl;
            round=10000;
        }

        int temp=strtol(argv[5],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert round failed: not a invalid number"<<endl;
            is_output= false;
        }
        if(temp==1)
            is_output= true;
        else if(temp!=0)
            cout<<"is_output should be 0 or 1, keep default 0"<<endl;

        blocks=strtol(argv[6],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert blocks failed: not a invalid number"<<endl;
            blocks=5;
        }

        temp=strtol(argv[7],&end_ptr,10);
        if (*end_ptr != '\0') {
            cout<<"convert contiguous_test failed: not a invalid number"<<endl;
            contiguous_test= false;
        }
        if(temp==1)
            contiguous_test= true;
        else if(temp!=0)
            cout<<"contiguous_test should be 0 or 1, keep default 0"<<endl;
    }
    cout<<"[args] "<<n<<" "<<q<<" "<<r<<" "<<round<<" "<<is_output<<" "<<blocks<<" "<<contiguous_test<<endl<<endl;

    n=1000000;
    cout<<"[SHVE bench] 10 times---------------------------------------"<<endl;
    for(int times=0;times<10;times++){
        SHVE_bench(n);
    }
//
//    cout<<"[SHVE-QF one round bench] 10 times--------------------------"<<endl;
//    for(int times=0;times<10;times++){
//        SHVE_QF_one_round_bench(n,q,r);
//    }

    n = 10;
    q = 28;
    r = 1;
//    round = 100000000;
    round = 1000000;
    blocks = 100;

//    cout<<"[SHVE-QF multi round bench]---------------------------------"<<endl;
//    SHVE_QF_multi_round_bench(n, q, r, round, is_output);


//    cout<<"[SHVE-QF multi round split quiet bench]---------------------"<<endl;
//    SHVE_QF_multi_round_split_quiet_bench(n, q, r, round, blocks);


//    cout<<"[QF bench]--------------------------------------------------"<<endl;
//    QF_bench(q, r, round, contiguous_test);


    return 0;
}
