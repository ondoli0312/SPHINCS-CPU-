#include "type.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/**
* @brief      ���� �� ����
* @param      result			��� ���� �迭
* @param      xLen				��� ����
* @return     ���� ���
*/
int randombytes(OUT u8* result, IN u64 xLen)
{
	for (int i = 0; i < xLen; i++) {
		result[i] = rand() % 0x100;
	}
	return SUCCESS;
}



/**
* @brief	seed�� ���� ���� Ű/���� Ű ����
* @brief	sk : [SK_SEED || SK_PRF || PUB_SEED || root]
* @brief	pk : [PUB_SEED || root]
* @param	pubkey		����Ű ������ �迭	
* @param    prikey		����Ű ������ �迭
* @return   ���� ���
*/
int generate_Key(OUT u8* pubkey, OUT u8* prikey)
{
	u8 SEED[SEED_BYTE];
	randombytes(SEED, SEED_BYTE);

	//������ SEED�� �������� Ű�� �ʱ�ȭ
	memcpy(prikey, SEED, SEED_BYTE);
	memcpy(pubkey, SEED + (2 * DIGEST), DIGEST);

	//�ؽ� �� �ʱ�ȭ(���Ŀ� ����� ���� �̸� �ʱ�ȭ�Ͽ� �ߺ������� ���)
	

	return SUCCESS;
}

int main() {
	srand(time(NULL));
}