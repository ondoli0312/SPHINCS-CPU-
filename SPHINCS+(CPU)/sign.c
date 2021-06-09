#include "type.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/**
* @brief      DIV�� �����Լ�, R<-RW+Ai�� ó��
* @param      bigint** R         ����ǰ� ������ bigint
* @param      word A            RW�� ���� ������ index word�� ������ ��
* @return      �Լ� ���� ���
*/
int randombytes(OUT u8* result, IN u64 xLen)
{
	for (int i = 0; i < xLen; i++) {
		result[i] = rand() % 0x100;
	}
}



int main() {
	srand(time(NULL));
}