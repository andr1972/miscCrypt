temp = (t3 & (t0 ^ t1)) ^ (t5 & t6) ^ (t4 & t2) ^ t0;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[0];
temp = (t2 & (t7 ^ t0)) ^ (t4 & t5) ^ (t3 & t1) ^ t7;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[1];
temp = (t1 & (t6 ^ t7)) ^ (t3 & t4) ^ (t2 & t0) ^ t6;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[2];
temp = (t0 & (t5 ^ t6)) ^ (t2 & t3) ^ (t1 & t7) ^ t5;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[3];
temp = (t7 & (t4 ^ t5)) ^ (t1 & t2) ^ (t0 & t6) ^ t4;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[4];
temp = (t6 & (t3 ^ t4)) ^ (t0 & t1) ^ (t7 & t5) ^ t3;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[5];
temp = (t5 & (t2 ^ t3)) ^ (t7 & t0) ^ (t6 & t4) ^ t2;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[6];
temp = (t4 & (t1 ^ t2)) ^ (t6 & t7) ^ (t5 & t3) ^ t1;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[7];

temp = (t3 & (t0 ^ t1)) ^ (t5 & t6) ^ (t4 & t2) ^ t0;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[8];
temp = (t2 & (t7 ^ t0)) ^ (t4 & t5) ^ (t3 & t1) ^ t7;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[9];
temp = (t1 & (t6 ^ t7)) ^ (t3 & t4) ^ (t2 & t0) ^ t6;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[10];
temp = (t0 & (t5 ^ t6)) ^ (t2 & t3) ^ (t1 & t7) ^ t5;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[11];
temp = (t7 & (t4 ^ t5)) ^ (t1 & t2) ^ (t0 & t6) ^ t4;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[12];
temp = (t6 & (t3 ^ t4)) ^ (t0 & t1) ^ (t7 & t5) ^ t3;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[13];
temp = (t5 & (t2 ^ t3)) ^ (t7 & t0) ^ (t6 & t4) ^ t2;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[14];
temp = (t4 & (t1 ^ t2)) ^ (t6 & t7) ^ (t5 & t3) ^ t1;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[15];

temp = (t3 & (t0 ^ t1)) ^ (t5 & t6) ^ (t4 & t2) ^ t0;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[16];
temp = (t2 & (t7 ^ t0)) ^ (t4 & t5) ^ (t3 & t1) ^ t7;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[17];
temp = (t1 & (t6 ^ t7)) ^ (t3 & t4) ^ (t2 & t0) ^ t6;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[18];
temp = (t0 & (t5 ^ t6)) ^ (t2 & t3) ^ (t1 & t7) ^ t5;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[19];
temp = (t7 & (t4 ^ t5)) ^ (t1 & t2) ^ (t0 & t6) ^ t4;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[20];
temp = (t6 & (t3 ^ t4)) ^ (t0 & t1) ^ (t7 & t5) ^ t3;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[21];
temp = (t5 & (t2 ^ t3)) ^ (t7 & t0) ^ (t6 & t4) ^ t2;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[22];
temp = (t4 & (t1 ^ t2)) ^ (t6 & t7) ^ (t5 & t3) ^ t1;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[23];

temp = (t3 & (t0 ^ t1)) ^ (t5 & t6) ^ (t4 & t2) ^ t0;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[24];
temp = (t2 & (t7 ^ t0)) ^ (t4 & t5) ^ (t3 & t1) ^ t7;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[25];
temp = (t1 & (t6 ^ t7)) ^ (t3 & t4) ^ (t2 & t0) ^ t6;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[26];
temp = (t0 & (t5 ^ t6)) ^ (t2 & t3) ^ (t1 & t7) ^ t5;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[27];
temp = (t7 & (t4 ^ t5)) ^ (t1 & t2) ^ (t0 & t6) ^ t4;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[28];
temp = (t6 & (t3 ^ t4)) ^ (t0 & t1) ^ (t7 & t5) ^ t3;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[29];
temp = (t5 & (t2 ^ t3)) ^ (t7 & t0) ^ (t6 & t4) ^ t2;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[30];
temp = (t4 & (t1 ^ t2)) ^ (t6 & t7) ^ (t5 & t3) ^ t1;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[31];

temp = (t1 & ((t6 & (~t0)) ^ (t2 & t5) ^ t3 ^ t4)) ^ (t2 & (t6 ^ t5)) ^
 (t0 & t5) ^ t4;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[5] + 0x452821e6L;
temp = (t0 & ((t5 & (~t7)) ^ (t1 & t4) ^ t2 ^ t3)) ^ (t1 & (t5 ^ t4)) ^
 (t7 & t4) ^ t3;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[14] + 0x38d01377L;
temp = (t7 & ((t4 & (~t6)) ^ (t0 & t3) ^ t1 ^ t2)) ^ (t0 & (t4 ^ t3)) ^
 (t6 & t3) ^ t2;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[26] - 0x41ab9931L;
temp = (t6 & ((t3 & (~t5)) ^ (t7 & t2) ^ t0 ^ t1)) ^ (t7 & (t3 ^ t2)) ^
 (t5 & t2) ^ t1;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[18] + 0x34e90c6cL;
temp = (t5 & ((t2 & (~t4)) ^ (t6 & t1) ^ t7 ^ t0)) ^ (t6 & (t2 ^ t1)) ^
 (t4 & t1) ^ t0;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[11] - 0x3f53d649L;
temp = (t4 & ((t1 & (~t3)) ^ (t5 & t0) ^ t6 ^ t7)) ^ (t5 & (t1 ^ t0)) ^
 (t3 & t0) ^ t7;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[28] - 0x3683af23L;
temp = (t3 & ((t0 & (~t2)) ^ (t4 & t7) ^ t5 ^ t6)) ^ (t4 & (t0 ^ t7)) ^
 (t2 & t7) ^ t6;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[7] + 0x3f84d5b5L;
temp = (t2 & ((t7 & (~t1)) ^ (t3 & t6) ^ t4 ^ t5)) ^ (t3 & (t7 ^ t6)) ^
 (t1 & t6) ^ t5;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[16] - 0x4ab8f6e9L;

temp = (t1 & ((t6 & (~t0)) ^ (t2 & t5) ^ t3 ^ t4)) ^ (t2 & (t6 ^ t5)) ^
 (t0 & t5) ^ t4;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[0] - 0x6de92a27L;
temp = (t0 & ((t5 & (~t7)) ^ (t1 & t4) ^ t2 ^ t3)) ^ (t1 & (t5 ^ t4)) ^
 (t7 & t4) ^ t3;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[23] - 0x768604e5L;
temp = (t7 & ((t4 & (~t6)) ^ (t0 & t3) ^ t1 ^ t2)) ^ (t0 & (t4 ^ t3)) ^
 (t6 & t3) ^ t2;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[20] - 0x2ecef45aL;
temp = (t6 & ((t3 & (~t5)) ^ (t7 & t2) ^ t0 ^ t1)) ^ (t7 & (t3 ^ t2)) ^
 (t5 & t2) ^ t1;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[22] - 0x67204a54L;
temp = (t5 & ((t2 & (~t4)) ^ (t6 & t1) ^ t7 ^ t0)) ^ (t6 & (t2 ^ t1)) ^
 (t4 & t1) ^ t0;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[1] + 0x2ffd72dbL;
temp = (t4 & ((t1 & (~t3)) ^ (t5 & t0) ^ t6 ^ t7)) ^ (t5 & (t1 ^ t0)) ^
 (t3 & t0) ^ t7;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[10] - 0x2fe52049L;
temp = (t3 & ((t0 & (~t2)) ^ (t4 & t7) ^ t5 ^ t6)) ^ (t4 & (t0 ^ t7)) ^
 (t2 & t7) ^ t6;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[4] - 0x471e5013L;
temp = (t2 & ((t7 & (~t1)) ^ (t3 & t6) ^ t4 ^ t5)) ^ (t3 & (t7 ^ t6)) ^
 (t1 & t6) ^ t5;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[8] + 0x6a267e96L;

temp = (t1 & ((t6 & (~t0)) ^ (t2 & t5) ^ t3 ^ t4)) ^ (t2 & (t6 ^ t5)) ^
 (t0 & t5) ^ t4;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[30] - 0x45836fbbL;
temp = (t0 & ((t5 & (~t7)) ^ (t1 & t4) ^ t2 ^ t3)) ^ (t1 & (t5 ^ t4)) ^
 (t7 & t4) ^ t3;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[3] - 0xed38067L;
temp = (t7 & ((t4 & (~t6)) ^ (t0 & t3) ^ t1 ^ t2)) ^ (t0 & (t4 ^ t3)) ^
 (t6 & t3) ^ t2;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[21] + 0x24a19947L;
temp = (t6 & ((t3 & (~t5)) ^ (t7 & t2) ^ t0 ^ t1)) ^ (t7 & (t3 ^ t2)) ^
 (t5 & t2) ^ t1;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[9] - 0x4c6e9309L;
temp = (t5 & ((t2 & (~t4)) ^ (t6 & t1) ^ t7 ^ t0)) ^ (t6 & (t2 ^ t1)) ^
 (t4 & t1) ^ t0;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[17] + 0x801f2e2L;
temp = (t4 & ((t1 & (~t3)) ^ (t5 & t0) ^ t6 ^ t7)) ^ (t5 & (t1 ^ t0)) ^
 (t3 & t0) ^ t7;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[24] - 0x7a7103eaL;
temp = (t3 & ((t0 & (~t2)) ^ (t4 & t7) ^ t5 ^ t6)) ^ (t4 & (t0 ^ t7)) ^
 (t2 & t7) ^ t6;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[29] + 0x636920d8L;
temp = (t2 & ((t7 & (~t1)) ^ (t3 & t6) ^ t4 ^ t5)) ^ (t3 & (t7 ^ t6)) ^
 (t1 & t6) ^ t5;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[6] + 0x71574e69L;

temp = (t1 & ((t6 & (~t0)) ^ (t2 & t5) ^ t3 ^ t4)) ^ (t2 & (t6 ^ t5)) ^
 (t0 & t5) ^ t4;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[19] - 0x5ba7015dL;
temp = (t0 & ((t5 & (~t7)) ^ (t1 & t4) ^ t2 ^ t3)) ^ (t1 & (t5 ^ t4)) ^
 (t7 & t4) ^ t3;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[12] - 0xb6cc282L;
temp = (t7 & ((t4 & (~t6)) ^ (t0 & t3) ^ t1 ^ t2)) ^ (t0 & (t4 ^ t3)) ^
 (t6 & t3) ^ t2;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[15] + 0xd95748fL;
temp = (t6 & ((t3 & (~t5)) ^ (t7 & t2) ^ t0 ^ t1)) ^ (t7 & (t3 ^ t2)) ^
 (t5 & t2) ^ t1;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[13] + 0x728eb658L;
temp = (t5 & ((t2 & (~t4)) ^ (t6 & t1) ^ t7 ^ t0)) ^ (t6 & (t2 ^ t1)) ^
 (t4 & t1) ^ t0;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[2] + 0x718bcd58L;
temp = (t4 & ((t1 & (~t3)) ^ (t5 & t0) ^ t6 ^ t7)) ^ (t5 & (t1 ^ t0)) ^
 (t3 & t0) ^ t7;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[25] - 0x7deab512L;
temp = (t3 & ((t0 & (~t2)) ^ (t4 & t7) ^ t5 ^ t6)) ^ (t4 & (t0 ^ t7)) ^
 (t2 & t7) ^ t6;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[31] + 0x7b54a41dL;
temp = (t2 & ((t7 & (~t1)) ^ (t3 & t6) ^ t4 ^ t5)) ^ (t3 & (t7 ^ t6)) ^
 (t1 & t6) ^ t5;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[27] - 0x3da5a64bL;

temp = (t6 & ((t2 & t0) ^ t1 ^ t5)) ^ (t2 & t3) ^ (t0 & t4) ^ t5;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[19] - 0x63cf2ac7L;
temp = (t5 & ((t1 & t7) ^ t0 ^ t4)) ^ (t1 & t2) ^ (t7 & t3) ^ t4;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[9] + 0x2af26013L;
temp = (t4 & ((t0 & t6) ^ t7 ^ t3)) ^ (t0 & t1) ^ (t6 & t2) ^ t3;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[4] - 0x3a2e4fddL;
temp = (t3 & ((t7 & t5) ^ t6 ^ t2)) ^ (t7 & t0) ^ (t5 & t1) ^ t2;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[20] + 0x286085f0L;
temp = (t2 & ((t6 & t4) ^ t5 ^ t1)) ^ (t6 & t7) ^ (t4 & t0) ^ t1;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[28] - 0x35be86e8L;
temp = (t1 & ((t5 & t3) ^ t4 ^ t0)) ^ (t5 & t6) ^ (t3 & t7) ^ t0;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[17] - 0x4724c711L;
temp = (t0 & ((t4 & t2) ^ t3 ^ t7)) ^ (t4 & t5) ^ (t2 & t6) ^ t7;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[8] - 0x71862350L;
temp = (t7 & ((t3 & t1) ^ t2 ^ t6)) ^ (t3 & t4) ^ (t1 & t5) ^ t6;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[22] + 0x603a180eL;

temp = (t6 & ((t2 & t0) ^ t1 ^ t5)) ^ (t2 & t3) ^ (t0 & t4) ^ t5;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[29] + 0x6c9e0e8bL;
temp = (t5 & ((t1 & t7) ^ t0 ^ t4)) ^ (t1 & t2) ^ (t7 & t3) ^ t4;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[14] - 0x4fe175c2L;
temp = (t4 & ((t0 & t6) ^ t7 ^ t3)) ^ (t0 & t1) ^ (t6 & t2) ^ t3;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[25] - 0x28ea883fL;
temp = (t3 & ((t7 & t5) ^ t6 ^ t2)) ^ (t7 & t0) ^ (t5 & t1) ^ t2;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[12] - 0x42ceb4d9L;
temp = (t2 & ((t6 & t4) ^ t5 ^ t1)) ^ (t6 & t7) ^ (t4 & t0) ^ t1;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[24] + 0x78af2fdaL;
temp = (t1 & ((t5 & t3) ^ t4 ^ t0)) ^ (t5 & t6) ^ (t3 & t7) ^ t0;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[30] + 0x55605c60L;
temp = (t0 & ((t4 & t2) ^ t3 ^ t7)) ^ (t4 & t5) ^ (t2 & t6) ^ t7;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[16] - 0x19aada0dL;
temp = (t7 & ((t3 & t1) ^ t2 ^ t6)) ^ (t3 & t4) ^ (t1 & t5) ^ t6;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[26] - 0x55aa546cL;

temp = (t6 & ((t2 & t0) ^ t1 ^ t5)) ^ (t2 & t3) ^ (t0 & t4) ^ t5;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[31] + 0x57489862L;
temp = (t5 & ((t1 & t7) ^ t0 ^ t4)) ^ (t1 & t2) ^ (t7 & t3) ^ t4;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[15] + 0x63e81440L;
temp = (t4 & ((t0 & t6) ^ t7 ^ t3)) ^ (t0 & t1) ^ (t6 & t2) ^ t3;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[7] + 0x55ca396aL;
temp = (t3 & ((t7 & t5) ^ t6 ^ t2)) ^ (t7 & t0) ^ (t5 & t1) ^ t2;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[3] + 0x2aab10b6L;
temp = (t2 & ((t6 & t4) ^ t5 ^ t1)) ^ (t6 & t7) ^ (t4 & t0) ^ t1;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[1] - 0x4b33a3ccL;
temp = (t1 & ((t5 & t3) ^ t4 ^ t0)) ^ (t5 & t6) ^ (t3 & t7) ^ t0;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[0] + 0x1141e8ceL;
temp = (t0 & ((t4 & t2) ^ t3 ^ t7)) ^ (t4 & t5) ^ (t2 & t6) ^ t7;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[18] - 0x5eab7951L;
temp = (t7 & ((t3 & t1) ^ t2 ^ t6)) ^ (t3 & t4) ^ (t1 & t5) ^ t6;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[27] + 0x7c72e993L;

temp = (t6 & ((t2 & t0) ^ t1 ^ t5)) ^ (t2 & t3) ^ (t0 & t4) ^ t5;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[13] - 0x4c11ebefL;
temp = (t5 & ((t1 & t7) ^ t0 ^ t4)) ^ (t1 & t2) ^ (t7 & t3) ^ t4;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[6] + 0x636fbc2aL;
temp = (t4 & ((t0 & t6) ^ t7 ^ t3)) ^ (t0 & t1) ^ (t6 & t2) ^ t3;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[21] + 0x2ba9c55dL;
temp = (t3 & ((t7 & t5) ^ t6 ^ t2)) ^ (t7 & t0) ^ (t5 & t1) ^ t2;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[10] + 0x741831f6L;
temp = (t2 & ((t6 & t4) ^ t5 ^ t1)) ^ (t6 & t7) ^ (t4 & t0) ^ t1;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[23] - 0x31a3c1eaL;
temp = (t1 & ((t5 & t3) ^ t4 ^ t0)) ^ (t5 & t6) ^ (t3 & t7) ^ t0;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[11] - 0x64786ce2L;
temp = (t0 & ((t4 & t2) ^ t3 ^ t7)) ^ (t4 & t5) ^ (t2 & t6) ^ t7;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[5] - 0x502945cdL;
temp = (t7 & ((t3 & t1) ^ t2 ^ t6)) ^ (t3 & t4) ^ (t1 & t5) ^ t6;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[2] + 0x6c24cf5cL;

temp = (t0 & ((t4 & (~t2)) ^ (t5 & (~t6)) ^ t1 ^ t6 ^ t3)) ^
 (t5 & ((t1 & t2) ^ t4 ^ t6)) ^ (t2 & t6) ^ t3;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[24] + 0x7a325381L;
temp = (t7 & ((t3 & (~t1)) ^ (t4 & (~t5)) ^ t0 ^ t5 ^ t2)) ^
 (t4 & ((t0 & t1) ^ t3 ^ t5)) ^ (t1 & t5) ^ t2;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[4] + 0x28958677L;
temp = (t6 & ((t2 & (~t0)) ^ (t3 & (~t4)) ^ t7 ^ t4 ^ t1)) ^
 (t3 & ((t7 & t0) ^ t2 ^ t4)) ^ (t0 & t4) ^ t1;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[0] + 0x3b8f4898L;
temp = (t5 & ((t1 & (~t7)) ^ (t2 & (~t3)) ^ t6 ^ t3 ^ t0)) ^
 (t2 & ((t6 & t7) ^ t1 ^ t3)) ^ (t7 & t3) ^ t0;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[14] + 0x6b4bb9afL;
temp = (t4 & ((t0 & (~t6)) ^ (t1 & (~t2)) ^ t5 ^ t2 ^ t7)) ^
 (t1 & ((t5 & t6) ^ t0 ^ t2)) ^ (t6 & t2) ^ t7;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[2] - 0x3b4017e5L;
temp = (t3 & ((t7 & (~t5)) ^ (t0 & (~t1)) ^ t4 ^ t1 ^ t6)) ^
 (t0 & ((t4 & t5) ^ t7 ^ t1)) ^ (t5 & t1) ^ t6;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[7] + 0x66282193L;
temp = (t2 & ((t6 & (~t4)) ^ (t7 & (~t0)) ^ t3 ^ t0 ^ t5)) ^
 (t7 & ((t3 & t4) ^ t6 ^ t0)) ^ (t4 & t0) ^ t5;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[28] + 0x61d809ccL;
temp = (t1 & ((t5 & (~t3)) ^ (t6 & (~t7)) ^ t2 ^ t7 ^ t4)) ^
 (t6 & ((t2 & t3) ^ t5 ^ t7)) ^ (t3 & t7) ^ t4;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[23] - 0x4de566fL;

temp = (t0 & ((t4 & (~t2)) ^ (t5 & (~t6)) ^ t1 ^ t6 ^ t3)) ^
 (t5 & ((t1 & t2) ^ t4 ^ t6)) ^ (t2 & t6) ^ t3;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[26] + 0x487cac60L;
temp = (t7 & ((t3 & (~t1)) ^ (t4 & (~t5)) ^ t0 ^ t5 ^ t2)) ^
 (t4 & ((t0 & t1) ^ t3 ^ t5)) ^ (t1 & t5) ^ t2;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[6] + 0x5dec8032L;
temp = (t6 & ((t2 & (~t0)) ^ (t3 & (~t4)) ^ t7 ^ t4 ^ t1)) ^
 (t3 & ((t7 & t0) ^ t2 ^ t4)) ^ (t0 & t4) ^ t1;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[30] - 0x107ba2a3L;
temp = (t5 & ((t1 & (~t7)) ^ (t2 & (~t3)) ^ t6 ^ t3 ^ t0)) ^
 (t2 & ((t6 & t7) ^ t1 ^ t3)) ^ (t7 & t3) ^ t0;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[20] - 0x167a8a4fL;
temp = (t4 & ((t0 & (~t6)) ^ (t1 & (~t2)) ^ t5 ^ t2 ^ t7)) ^
 (t1 & ((t5 & t6) ^ t0 ^ t2)) ^ (t6 & t2) ^ t7;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[18] - 0x23d9dcfeL;
temp = (t3 & ((t7 & (~t5)) ^ (t0 & (~t1)) ^ t4 ^ t1 ^ t6)) ^
 (t0 & ((t4 & t5) ^ t7 ^ t1)) ^ (t5 & t1) ^ t6;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[25] - 0x149ae478L;
temp = (t2 & ((t6 & (~t4)) ^ (t7 & (~t0)) ^ t3 ^ t0 ^ t5)) ^
 (t7 & ((t3 & t4) ^ t6 ^ t0)) ^ (t4 & t0) ^ t5;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[19] + 0x23893e81L;
temp = (t1 & ((t5 & (~t3)) ^ (t6 & (~t7)) ^ t2 ^ t7 ^ t4)) ^
 (t6 & ((t2 & t3) ^ t5 ^ t7)) ^ (t3 & t7) ^ t4;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[3] - 0x2c69533bL;

temp = (t0 & ((t4 & (~t2)) ^ (t5 & (~t6)) ^ t1 ^ t6 ^ t3)) ^
 (t5 & ((t1 & t2) ^ t4 ^ t6)) ^ (t2 & t6) ^ t3;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[22] + 0xf6d6ff3L;
temp = (t7 & ((t3 & (~t1)) ^ (t4 & (~t5)) ^ t0 ^ t5 ^ t2)) ^
 (t4 & ((t0 & t1) ^ t3 ^ t5)) ^ (t1 & t5) ^ t2;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[11] - 0x7c0bbdc7L;
temp = (t6 & ((t2 & (~t0)) ^ (t3 & (~t4)) ^ t7 ^ t4 ^ t1)) ^
 (t3 & ((t7 & t0) ^ t2 ^ t4)) ^ (t0 & t4) ^ t1;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[31] + 0x2e0b4482L;
temp = (t5 & ((t1 & (~t7)) ^ (t2 & (~t3)) ^ t6 ^ t3 ^ t0)) ^
 (t2 & ((t6 & t7) ^ t1 ^ t3)) ^ (t7 & t3) ^ t0;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[21] - 0x5b7bdffcL;
temp = (t4 & ((t0 & (~t6)) ^ (t1 & (~t2)) ^ t5 ^ t2 ^ t7)) ^
 (t1 & ((t5 & t6) ^ t0 ^ t2)) ^ (t6 & t2) ^ t7;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[8] + 0x69c8f04aL;
temp = (t3 & ((t7 & (~t5)) ^ (t0 & (~t1)) ^ t4 ^ t1 ^ t6)) ^
 (t0 & ((t4 & t5) ^ t7 ^ t1)) ^ (t5 & t1) ^ t6;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[27] - 0x61e064a2L;
temp = (t2 & ((t6 & (~t4)) ^ (t7 & (~t0)) ^ t3 ^ t0 ^ t5)) ^
 (t7 & ((t3 & t4) ^ t6 ^ t0)) ^ (t4 & t0) ^ t5;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[12] + 0x21c66842L;
temp = (t1 & ((t5 & (~t3)) ^ (t6 & (~t7)) ^ t2 ^ t7 ^ t4)) ^
 (t6 & ((t2 & t3) ^ t5 ^ t7)) ^ (t3 & t7) ^ t4;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[9] - 0x9169366L;

temp = (t0 & ((t4 & (~t2)) ^ (t5 & (~t6)) ^ t1 ^ t6 ^ t3)) ^
 (t5 & ((t1 & t2) ^ t4 ^ t6)) ^ (t2 & t6) ^ t3;
t7 = (((temp) >> 7) | (temp << 25)) +
     (((t7) >> 11) | (t7 << 21)) + W[1] + 0x670c9c61L;
temp = (t7 & ((t3 & (~t1)) ^ (t4 & (~t5)) ^ t0 ^ t5 ^ t2)) ^
 (t4 & ((t0 & t1) ^ t3 ^ t5)) ^ (t1 & t5) ^ t2;
t6 = (((temp) >> 7) | (temp << 25)) +
     (((t6) >> 11) | (t6 << 21)) + W[29] - 0x542c7710L;
temp = (t6 & ((t2 & (~t0)) ^ (t3 & (~t4)) ^ t7 ^ t4 ^ t1)) ^
 (t3 & ((t7 & t0) ^ t2 ^ t4)) ^ (t0 & t4) ^ t1;
t5 = (((temp) >> 7) | (temp << 25)) +
     (((t5) >> 11) | (t5 << 21)) + W[5] + 0x6a51a0d2L;
temp = (t5 & ((t1 & (~t7)) ^ (t2 & (~t3)) ^ t6 ^ t3 ^ t0)) ^
 (t2 & ((t6 & t7) ^ t1 ^ t3)) ^ (t7 & t3) ^ t0;
t4 = (((temp) >> 7) | (temp << 25)) +
     (((t4) >> 11) | (t4 << 21)) + W[15] - 0x27abd098L;
temp = (t4 & ((t0 & (~t6)) ^ (t1 & (~t2)) ^ t5 ^ t2 ^ t7)) ^
 (t1 & ((t5 & t6) ^ t0 ^ t2)) ^ (t6 & t2) ^ t7;
t3 = (((temp) >> 7) | (temp << 25)) +
     (((t3) >> 11) | (t3 << 21)) + W[17] - 0x69f058d8L;
temp = (t3 & ((t7 & (~t5)) ^ (t0 & (~t1)) ^ t4 ^ t1 ^ t6)) ^
 (t0 & ((t4 & t5) ^ t7 ^ t1)) ^ (t5 & t1) ^ t6;
t2 = (((temp) >> 7) | (temp << 25)) +
     (((t2) >> 11) | (t2 << 21)) + W[10] - 0x54aecc5dL;
temp = (t2 & ((t6 & (~t4)) ^ (t7 & (~t0)) ^ t3 ^ t0 ^ t5)) ^
 (t7 & ((t3 & t4) ^ t6 ^ t0)) ^ (t4 & t0) ^ t5;
t1 = (((temp) >> 7) | (temp << 25)) +
     (((t1) >> 11) | (t1 << 21)) + W[16] + 0x6eef0b6cL;
temp = (t1 & ((t5 & (~t3)) ^ (t6 & (~t7)) ^ t2 ^ t7 ^ t4)) ^
 (t6 & ((t2 & t3) ^ t5 ^ t7)) ^ (t3 & t7) ^ t4;
t0 = (((temp) >> 7) | (temp << 25)) +
     (((t0) >> 11) | (t0 << 21)) + W[13] + 0x137a3be4L;
