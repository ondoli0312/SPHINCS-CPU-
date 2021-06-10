#include "type.h"
#include "SHA-256.h"

void OP_SHA256(IN const u8* pt, IN unsigned long long byte_msglen, OUT u8* hash_value);
void OP_SHA256_Process(IN u8* pt, IN u32 byte_msglen, OUT SHA256_INFO* info);
void OP_SHA256_Final(OUT SHA256_INFO* info, OUT u8* hash_value);
const u32 cont[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void Hash_Block(IN u32* const pt)
{
	u32 W[64], a, b, c, d, e, f, g, h, temp1 = 0, temp2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		W[i] = ENDIAN_CHANGE(pt[i]);


	for (i = 16; i < 64; i++)
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);

	a = state_seed[0];
	b = state_seed[1];
	c = state_seed[2];
	d = state_seed[3];
	e = state_seed[4];
	f = state_seed[5];
	g = state_seed[6];
	h = state_seed[7];

	
	for (i = 0; i < 64; i++)
	{
		temp1 = h + BS1(e) + Ch(e, f, g) + cont[i] + W[i];
		temp2 = (BS0(a)) + (Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state_seed[0] += a;
	state_seed[1] += b;
	state_seed[2] += c;
	state_seed[3] += d;
	state_seed[4] += e;
	state_seed[5] += f;
	state_seed[6] += g;
	state_seed[7] += h;

}


/**
* @brief      중복적으로 사용하는 SEED 값 해시 블록 연산 초기화
* @param      pubkey			공개 키 SEED
* @return     실행 결과
*/
int init_Hash_func(IN u8* pubkey)
{
	u8 BLOCK[HASHBLOCK];
	u32 i = 0;

	for (i = 0; i < DIGEST; i++)
		BLOCK[i] = pubkey[i];
	for (i = DIGEST; i < HASHBLOCK; i++)
		BLOCK[i] = 0;

	//init seed state
	state_seed[0] = 0x6a09e667;
	state_seed[1] = 0xbb67ae85;
	state_seed[2] = 0x3c6ef372;
	state_seed[3] = 0xa54ff53a;
	state_seed[4] = 0x510e527f;
	state_seed[5] = 0x9b05688c;
	state_seed[6] = 0x1f83d9ab;
	state_seed[7] = 0x5be0cd19;
	state_seed[8] = 0;
	
	Hash_Block((u32*)BLOCK);
	state_seed[8] = 0;
	state_seed[9] = 0x00000040;

}

void SHA256_inc_info(SHA256_INFO* info, u32* state) {

	info->hash[0] = state[0];
	info->hash[1] = state[1];
	info->hash[2] = state[2];
	info->hash[3] = state[3];
	info->hash[4] = state[4];
	info->hash[5] = state[5];
	info->hash[6] = state[6];
	info->hash[7] = state[7];

	info->byte_msglen = 0;

	memset((u8*)info->buf, 0, BLOCKBYTE);
}

void Inc_SHA256(IN const u8* pt, u32* state, IN unsigned long long byte_msglen, OUT u8* hash_value)
{

	SHA256_INFO info;
	SHA256_inc_info(&info, state);
	OP_SHA256_Process(pt, byte_msglen, &info);
	OP_SHA256_Final(&info, hash_value);
	state[0] = info.hash[0];
	state[1] = info.hash[1];
	state[2] = info.hash[2];
	state[3] = info.hash[3];
	state[4] = info.hash[4];
	state[5] = info.hash[5];
	state[6] = info.hash[6];
	state[7] = info.hash[7];

}

void SHA256_inc_final(u8* output, u32* state, u8* in ,u64 xLen) {
	u8 pad[128];
	u64 len = ((u32*)(state))[9] + xLen;
	Inc_SHA256(in, state, xLen, output);
}

void M_SHA256_init(OUT SHA256_INFO* info)
{
	info->hash[0] = 0x6a09e667;
	info->hash[1] = 0xbb67ae85;
	info->hash[2] = 0x3c6ef372;
	info->hash[3] = 0xa54ff53a;
	info->hash[4] = 0x510e527f;
	info->hash[5] = 0x9b05688c;
	info->hash[6] = 0x1f83d9ab;
	info->hash[7] = 0x5be0cd19;

	info->byte_msglen = 0;

	memset((u8*)info->buf, 0, BLOCKBYTE);
}


void M_Block(IN u32* const pt, OUT SHA256_INFO* info)
{
	u32 W[64], a, b, c, d, e, f, g, h, temp1 = 0, temp2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		W[i] = ENDIAN_CHANGE(pt[i]);


	for (i = 16; i < 64; i++)
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);

	a = info->hash[0];
	b = info->hash[1];
	c = info->hash[2];
	d = info->hash[3];
	e = info->hash[4];
	f = info->hash[5];
	g = info->hash[6];
	h = info->hash[7];

	for (i = 0; i < 64; i++)
	{
		temp1 = h + BS1(e) + Ch(e, f, g) + cont[i] + W[i];
		temp2 = (BS0(a)) + (Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	info->hash[0] += a;
	info->hash[1] += b;
	info->hash[2] += c;
	info->hash[3] += d;
	info->hash[4] += e;
	info->hash[5] += f;
	info->hash[6] += g;
	info->hash[7] += h;

}


void M_SHA256_Process(IN u8* pt, IN u32 byte_msglen, OUT SHA256_INFO* info)
{
	info->byte_msglen += byte_msglen;

	while (byte_msglen >= BLOCKBYTE)
	{
		memcpy((u8*)info->buf, pt, (BLOCKBYTE));
		M_Block((u32*)info->buf, info);
		pt += BLOCKBYTE;
		byte_msglen -= BLOCKBYTE;
	}

	memcpy((u8*)info->buf, pt, (byte_msglen));
}

void M_SHA256_Final(OUT SHA256_INFO* info, OUT u8* hash_value)
{
	u32 final_byte = 0;

	final_byte = (info->byte_msglen) % BLOCKBYTE;

	info->buf[final_byte++] = 0x80;

	if (final_byte > BLOCKBYTE - 8) //448bit ÀÌ»ó

	{
		memset((u8*)info->buf + final_byte, 0, BLOCKBYTE - final_byte);
		M_Block((u32*)info->buf, info);
		memset((u8*)info->buf, 0, BLOCKBYTE - 8);	//zero padding
	}

	else//final_bit <<448
		memset((u8*)info->buf + final_byte, 0, BLOCKBYTE - final_byte - 8);

	((u32*)info->buf)[BLOCKBYTE / 4 - 2] = ENDIAN_CHANGE(((info->byte_msglen) >> 29));
	((u32*)info->buf)[BLOCKBYTE / 4 - 1] = ENDIAN_CHANGE(((info->byte_msglen) << 3) & 0xffffffff);

	M_Block((u32*)info->buf, info);

	hash_value[0] = (info->hash[0] >> 24) & 0xff;
	hash_value[1] = (info->hash[0] >> 16) & 0xff;
	hash_value[2] = (info->hash[0] >> 8) & 0xff;
	hash_value[3] = (info->hash[0]) & 0xff;

	hash_value[4] = (info->hash[1] >> 24) & 0xff;
	hash_value[5] = (info->hash[1] >> 16) & 0xff;
	hash_value[6] = (info->hash[1] >> 8) & 0xff;
	hash_value[7] = (info->hash[1]) & 0xff;

	hash_value[8] = (info->hash[2] >> 24) & 0xff;
	hash_value[9] = (info->hash[2] >> 16) & 0xff;
	hash_value[10] = (info->hash[2] >> 8) & 0xff;
	hash_value[11] = (info->hash[2]) & 0xff;

	hash_value[12] = (info->hash[3] >> 24) & 0xff;
	hash_value[13] = (info->hash[3] >> 16) & 0xff;
	hash_value[14] = (info->hash[3] >> 8) & 0xff;
	hash_value[15] = (info->hash[3]) & 0xff;

	hash_value[16] = (info->hash[4] >> 24) & 0xff;
	hash_value[17] = (info->hash[4] >> 16) & 0xff;
	hash_value[18] = (info->hash[4] >> 8) & 0xff;
	hash_value[19] = (info->hash[4]) & 0xff;

	hash_value[20] = (info->hash[5] >> 24) & 0xff;
	hash_value[21] = (info->hash[5] >> 16) & 0xff;
	hash_value[22] = (info->hash[5] >> 8) & 0xff;
	hash_value[23] = (info->hash[5]) & 0xff;

	hash_value[24] = (info->hash[6] >> 24) & 0xff;
	hash_value[25] = (info->hash[6] >> 16) & 0xff;
	hash_value[26] = (info->hash[6] >> 8) & 0xff;
	hash_value[27] = (info->hash[6]) & 0xff;

	hash_value[28] = (info->hash[7] >> 24) & 0xff;
	hash_value[29] = (info->hash[7] >> 16) & 0xff;
	hash_value[30] = (info->hash[7] >> 8) & 0xff;
	hash_value[31] = (info->hash[7]) & 0xff;
}

void M_SHA256(IN const u8* pt, IN unsigned long long byte_msglen, OUT u8* hash_value)
{

	SHA256_INFO info;
	M_SHA256_init(&info);
	M_SHA256_Process(pt, byte_msglen, &info);
	M_SHA256_Final(&info, hash_value);
}

void OP_Block(IN u32* const pt, OUT SHA256_INFO* info)
{
	u32 W[64], a, b, c, d, e, f, g, h;
	u32 temp1[4];
	u32 temp2[4];
	int i = 0;


	for (i = 0; i < 16; i++)
		W[i] = ENDIAN_CHANGE(pt[i]);
	for (i = 16; i < 64; i++)
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);


	a = info->hash[0];
	b = info->hash[1];
	c = info->hash[2];
	d = info->hash[3];
	e = info->hash[4];
	f = info->hash[5];
	g = info->hash[6];
	h = info->hash[7];
	u32 value = 0;
	for (i = 3; i < 64; i += 4) {

		temp1[0] = h + BS1(e) + Ch(e, f, g) + cont[i - 3] + W[i - 3];
		temp1[1] = g + BS1(d + temp1[0]) + Ch(d + temp1[0], e, f) + cont[i - 2] + W[i - 2];
		temp1[2] = f + BS1(c + temp1[1]) + Ch(c + temp1[1], d + temp1[0], e) + cont[i - 1] + W[i - 1];
		temp1[3] = e + BS1(b + temp1[2]) + Ch(b + temp1[2], c + temp1[1], d + temp1[0]) + cont[i] + W[i];



		temp2[0] = BS0(a) + (Maj(a, b, c));
		temp2[1] = BS0(temp1[0] + temp2[0]) + Maj(temp1[0] + temp2[0], a, b);
		temp2[2] = BS0(temp1[1] + temp2[1]) + Maj(temp1[1] + temp2[1], temp1[0] + temp2[0], a);
		temp2[3] = BS0(temp1[2] + temp2[2]) + Maj(temp1[2] + temp2[2], temp1[1] + temp2[1], temp1[0] + temp2[0]);

		h = d + temp1[0];
		g = c + temp1[1];
		f = b + temp1[2];
		e = a + temp1[3];
		d = temp1[0] + temp2[0];
		c = temp1[1] + temp2[1];
		b = temp1[2] + temp2[2];
		a = temp1[3] + temp2[3];
	}


	info->hash[0] += a;
	info->hash[1] += b;
	info->hash[2] += c;
	info->hash[3] += d;
	info->hash[4] += e;
	info->hash[5] += f;
	info->hash[6] += g;
	info->hash[7] += h;

}

void OP_SHA256_Process(IN u8* pt, IN u32 byte_msglen, OUT SHA256_INFO* info)
{
	info->byte_msglen += byte_msglen;

	while (byte_msglen >= BLOCKBYTE)
	{
		memcpy((u8*)info->buf, pt, (BLOCKBYTE));
		OP_Block((u32*)info->buf, info);
		pt += BLOCKBYTE;
		byte_msglen -= BLOCKBYTE;
	}

	memcpy((u8*)info->buf, pt, (byte_msglen));
}


void OP_SHA256_Final(OUT SHA256_INFO* info, OUT u8* hash_value)
{
	u32 final_byte = 0;

	final_byte = (info->byte_msglen) % BLOCKBYTE;

	info->buf[final_byte++] = 0x80;

	if (final_byte > BLOCKBYTE - 8) //448bit ÀÌ»ó

	{
		memset((u8*)info->buf + final_byte, 0, BLOCKBYTE - final_byte);
		OP_Block((u32*)info->buf, info);
		memset((u8*)info->buf, 0, BLOCKBYTE - 8);	//zero padding
	}

	else//final_bit <<448
		memset((u8*)info->buf + final_byte, 0, BLOCKBYTE - final_byte - 8);

	((u32*)info->buf)[BLOCKBYTE / 4 - 2] = ENDIAN_CHANGE(((info->byte_msglen) >> 29));
	((u32*)info->buf)[BLOCKBYTE / 4 - 1] = ENDIAN_CHANGE(((info->byte_msglen) << 3) & 0xffffffff);

	OP_Block((u32*)info->buf, info);

	hash_value[0] = (info->hash[0] >> 24) & 0xff;
	hash_value[1] = (info->hash[0] >> 16) & 0xff;
	hash_value[2] = (info->hash[0] >> 8) & 0xff;
	hash_value[3] = (info->hash[0]) & 0xff;

	hash_value[4] = (info->hash[1] >> 24) & 0xff;
	hash_value[5] = (info->hash[1] >> 16) & 0xff;
	hash_value[6] = (info->hash[1] >> 8) & 0xff;
	hash_value[7] = (info->hash[1]) & 0xff;

	hash_value[8] = (info->hash[2] >> 24) & 0xff;
	hash_value[9] = (info->hash[2] >> 16) & 0xff;
	hash_value[10] = (info->hash[2] >> 8) & 0xff;
	hash_value[11] = (info->hash[2]) & 0xff;

	hash_value[12] = (info->hash[3] >> 24) & 0xff;
	hash_value[13] = (info->hash[3] >> 16) & 0xff;
	hash_value[14] = (info->hash[3] >> 8) & 0xff;
	hash_value[15] = (info->hash[3]) & 0xff;

	hash_value[16] = (info->hash[4] >> 24) & 0xff;
	hash_value[17] = (info->hash[4] >> 16) & 0xff;
	hash_value[18] = (info->hash[4] >> 8) & 0xff;
	hash_value[19] = (info->hash[4]) & 0xff;

	hash_value[20] = (info->hash[5] >> 24) & 0xff;
	hash_value[21] = (info->hash[5] >> 16) & 0xff;
	hash_value[22] = (info->hash[5] >> 8) & 0xff;
	hash_value[23] = (info->hash[5]) & 0xff;

	hash_value[24] = (info->hash[6] >> 24) & 0xff;
	hash_value[25] = (info->hash[6] >> 16) & 0xff;
	hash_value[26] = (info->hash[6] >> 8) & 0xff;
	hash_value[27] = (info->hash[6]) & 0xff;

	hash_value[28] = (info->hash[7] >> 24) & 0xff;
	hash_value[29] = (info->hash[7] >> 16) & 0xff;
	hash_value[30] = (info->hash[7] >> 8) & 0xff;
	hash_value[31] = (info->hash[7]) & 0xff;
}


void OP_SHA256(IN const u8* pt, IN unsigned long long byte_msglen, OUT u8* hash_value)
{

	SHA256_INFO info;
	M_SHA256_init(&info);
	OP_SHA256_Process(pt, byte_msglen, &info);
	OP_SHA256_Final(&info, hash_value);
}