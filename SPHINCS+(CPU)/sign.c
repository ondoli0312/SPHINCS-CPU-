#include "type.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/**
* @brief      DIV의 내부함수, R<-RW+Ai를 처리
* @param      bigint** R         연산되고 저장할 bigint
* @param      word A            RW의 가장 최하위 index word에 더해질 값
* @return      함수 실행 결과
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