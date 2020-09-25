# DCPCryptCpp
Cryptographic Component Library DCPCrypt translated from Pascal to C++

Hashes from DCPCrypt:
- Haval
- MD4
- MD5
- Rimpemd128
- Rimpemd160
- Sha1-160
- Sha2-256

Updates:
Haval gives odd results, remained and renamed to HavalPas, add new Haval
Sha3 for 224,256,385 and 512 in one tiny, self explained but fast class.
not exists yet:
Sha2-512
Tiger

Ciphers from DCPCrypt:
- Blowfish
- Rijndael
- Serpent
- Twofish
not exists yet:
- Cast128
- Cast256
- DES
- Gost
- ICE
- Dea
- Mars
- Misty1
- RC2
- RC4
- RC5
- RC6
- Tea

Correct: reset index in Compress

Hash and cipher classes are low-level without stream handling etc.
Two test programs: testSpeed and hashFiles
testSpeed give with Visual Studio, Intel i3 3 GHz

Time of 100000 bytes
- ....
- md4 elapsed=127 us
- md5 elapsed=189 us
- ripemd-128 elapsed=242 us
- ripemd-160 elapsed=367 us
- sha1-160 elapsed=245 us
- sha2-256 elapsed=476 us
- sha3-224 elapsed=352 us
- sha3-256 elapsed=375 us
- sha3-384 elapsed=490 us
- sha3-512 elapsed=705 us

Time of 100000 bytes
- blowfish : 833 us
- rijndael : 389 us
- serpent : 1143 us
- twofish : 617 us

