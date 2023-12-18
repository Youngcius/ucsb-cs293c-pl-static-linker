#include <stdio.h>
#include "vector.h"


int x[2] = {1,2};
int y[2] = {3,4};
int sum[2];
int prod[2];

int main(int argc, char const *argv[])
{
    addvec(x, y, sum, 2);
    multvec(x, y, prod, 2);
    printf("x = [%d, %d], y = [%d, %d]\n", x[0], x[1], y[0], y[1]);
    printf("sum = [%d, %d], prod = [%d, %d]\n", sum[0], sum[1], prod[0], prod[1]);
    return 0;
}
