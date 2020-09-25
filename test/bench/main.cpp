#include <iostream>
#include "DCPh_haval.h"
#include "DCPh_md4.h"
#include "DCPh_md5.h"
#include "DCPh_ripemd128.h"
#include "DCPh_ripemd160.h"
#include "DCPh_sha1_160.h"
#include "DCPh_sha2_256.h"
#include "DCPh_sha3.h"
#include "DCPc_rijndael.h"
#include "DCPc_serpent.h"
#include "DCPc_blowfish.h"
#include "DCPc_twofish.h"
#include "../../Argon2/argon2.h"
#include <chrono>
#include <vector>
#include <climits>
#include <cstring>

using namespace std;
using namespace dcpcrypt;

void fillHashVec(vector<DCP_hash*> &vec)
{
    for (int digestBits = 128; digestBits <= 256; digestBits += 32)
        for (int passCount = 3; passCount <= 5; passCount++)
        {
            vec.push_back(new DCPh_haval(digestBits, passCount));
        }
    vec.push_back(new DCPh_md4());
    vec.push_back(new DCPh_md5());
    vec.push_back(new DCPh_ripemd128());
    vec.push_back(new DCPh_ripemd160());
    vec.push_back(new DCPh_sha1_160());
    vec.push_back(new DCPh_sha2_256());
    vec.push_back(new DCPh_sha3(224));
    vec.push_back(new DCPh_sha3(256));
    vec.push_back(new DCPh_sha3(384));
    vec.push_back(new DCPh_sha3(512));
}

void fillCipherVec(vector<DCP_cipher*> &vec)
{
    vec.push_back(new DCPc_blowfish());
    vec.push_back(new DCPc_rijndael());
    vec.push_back(new DCPc_serpent());
    vec.push_back(new DCPc_twofish());
}

void freeHashVec(vector<DCP_hash*> &vec)
{
    for (size_t i = 0; i < vec.size(); i++)
        delete vec[i];
    vec.clear();
}

void freeCipherVec(vector<DCP_cipher*> &vec)
{
    for (size_t i = 0; i < vec.size(); i++)
        delete vec[i];
    vec.clear();
}

void testHashesSpeed()
{
    vector<DCP_hash*> vec;
    fillHashVec(vec);
    const int size = 100000;
    const int loop = 1;
    const int ntrials = 100;
    printf("\nTime of %d bytes\n", size*loop);
    uint8_t *buf = new uint8_t[size];
    for (int i = 0; i < size; i++)
        buf[i] = (uint8_t)i;
    for (int i = 0; i < vec.size(); i++)
    {
        uint8_t digest[64];
        DCP_hash * hash = vec[i];
        bool selfTest = hash->selfTest();
        if (selfTest)
        {
            long long minElapsed = LLONG_MAX;
            for (int j = 0; j < ntrials; j++)
            {
                chrono::time_point<chrono::system_clock> start = chrono::system_clock::now();
                hash->init();
                for (int k = 0; k < loop; k++)
                    hash->update(buf, size);
                hash->final(digest);
                auto current = chrono::system_clock::now();
                long long elapsed = chrono::duration_cast<chrono::nanoseconds>(current - start).count();
                if (elapsed < minElapsed)minElapsed = elapsed;
            }
            printf("%s elapsed=%lld us\n", hash->getAlgorithm().c_str(), minElapsed);
        }
        else printf("%s : selfTest error\n", hash->getAlgorithm().c_str());
    }
    delete buf;
    freeHashVec(vec);
}


void testCiphersSpeed()
{
    vector<DCP_cipher*> vec;
    fillCipherVec(vec);
    const int size = 100000;
    const int ntrials = 100;
    printf("\nTime of %d bytes\n", size);
    unsigned char* bufIn = new unsigned char[size];
    unsigned char* bufOut = new unsigned char[size];
    string strkey = "1234123412341234";
    memset(bufIn, 0xa0, size);
    for (int i = 0; i < vec.size(); i++)
    {
        DCP_cipher * cipher = vec[i];
        bool selfTest = cipher->selfTest();
        if (selfTest)
        {
            cipher->init((uint8_t*)strkey.c_str(), strkey.length() * 8, nullptr);
            long long minElapsed = LLONG_MAX;
            for (int j = 0; j < ntrials; j++)
            {
                chrono::time_point<chrono::system_clock> start = chrono::system_clock::now();
                ((DCP_blockcipher*)cipher)->encryptCBC(bufIn, bufOut, size);
                auto current = chrono::system_clock::now();
                long long elapsed = chrono::duration_cast<chrono::nanoseconds>(current - start).count();
                if (elapsed < minElapsed)minElapsed = elapsed;
            }
            printf("%s : %lld us\n", cipher->getAlgorithm().c_str(), minElapsed);
        }
        else printf("%s : selfTest error\n", cipher->getAlgorithm().c_str());
    }
    delete bufIn;
    delete bufOut;
    freeCipherVec(vec);
}

void selfTest() {
    DCPh_haval havel;
    havel.selfTest();
    DCPh_md4 md4;
    md4.selfTest();
    DCPh_md5 md5;
    md5.selfTest();
    DCPh_ripemd128 ripemd128;
    ripemd128.selfTest();
    DCPh_ripemd160 ripemd160;
    ripemd160.selfTest();
    DCPh_sha1_160 sha1;
    sha1.selfTest();
    DCPh_sha2_256 sha2;
    sha2.selfTest();
    DCPh_sha3 sha3_224(256);
    sha3_224.selfTest();
    DCPh_sha3 sha3_256(256);
    sha3_256.selfTest();
    DCPh_sha3 sha3_384(256);
    sha3_384.selfTest();
    DCPh_sha3 sha3_512(256);
    sha3_512.selfTest();

    DCPc_rijndael rijndael;
    rijndael.selfTest();
    DCPc_serpent serpent;
    serpent.selfTest();
    DCPc_blowfish blowfish;
    blowfish.selfTest();
    DCPc_twofish twofish;
    twofish.selfTest();
}

void ArgonBenchmark() {
    const uint32_t inlen = 16;
    const unsigned outlen=16;
    unsigned char out[outlen];
    unsigned char pwd_array[inlen];
    unsigned char salt_array[inlen];

    uint32_t t_cost = 1;

    memset(pwd_array, 0, inlen);
    memset(salt_array, 1, inlen);
    vector<uint32_t> thread_test = {1, 2, 4, 6, 8, 16};

    for (uint32_t m_cost = (uint32_t) 1 << 18; m_cost <= (uint32_t) 1 << 22; m_cost *= 2) {
        for (uint32_t thread_n : thread_test) {

            chrono::time_point<chrono::system_clock> start_cycles, stop_cycles, stop_cycles_i, stop_cycles_di, stop_cycles_ds;

            clock_t start_time = clock();
            start_cycles = chrono::system_clock::now();

            argon2::Argon2_Context context(out, outlen, pwd_array, inlen, salt_array, inlen, NULL, 0, NULL, 0,
                                   t_cost, m_cost, thread_n, thread_n,NULL,NULL,false,false, false,false);
            Argon2d(&context);
            stop_cycles = chrono::system_clock::now();
            Argon2i(&context);
            stop_cycles_i = chrono::system_clock::now();
            Argon2id(&context);
            stop_cycles_di = chrono::system_clock::now();
            Argon2ds(&context);
            stop_cycles_ds = chrono::system_clock::now();
            clock_t stop_time = clock();

            uint64_t delta_d0 = chrono::duration_cast<chrono::nanoseconds>(stop_cycles - start_cycles).count();
            uint64_t delta_d = delta_d0/ m_cost;
            uint64_t delta_i0 = chrono::duration_cast<chrono::nanoseconds>(stop_cycles_i - stop_cycles).count();
            uint64_t delta_i = delta_i0 / m_cost;
            uint64_t delta_id0 = chrono::duration_cast<chrono::nanoseconds>(stop_cycles_di - stop_cycles_i).count();
            uint64_t delta_id = delta_id0 / m_cost;
            uint64_t delta_ds0 = chrono::duration_cast<chrono::nanoseconds>(stop_cycles_ds - stop_cycles_di).count();
            uint64_t delta_ds = delta_ds0 / m_cost;

            float mcycles_d = (float) (delta_d0) / (1 << 20);
            float mcycles_i = (float) (delta_i0) / (1 << 20);
            float mcycles_id = (float) (delta_id0) / (1 << 20);
            float mcycles_ds = (float) (delta_ds0) / (1 << 20);
            printf("Argon2d %d pass(es)  %d Mbytes %d lanes/threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_d / 1024, mcycles_d);
            printf("Argon2i %d pass(es)  %d Mbytes %d lanes/threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_i / 1024, mcycles_i);
            printf("Argon2id %d pass(es)  %d Mbytes %d lanes/threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_id / 1024, mcycles_id);
            printf("Argon2ds %d pass(es)  %d Mbytes %d lanes/threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_ds / 1024, mcycles_ds);

            float run_time = ((float) stop_time - start_time) / (CLOCKS_PER_SEC);
            printf("%2.4f seconds\n\n", run_time);
        }
    }
}

int main(int argc, char * argv[])
{
    //testHashesSpeed();
    //testCiphersSpeed();
    //selfTest()
    ArgonBenchmark();
    return 0;
}
