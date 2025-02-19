#include <stdio.h>

int 
__cdecl addme(short a, short b)
{
    return a+b;
}

int main()
{
    short x = 4;
    short y = 5;
    short sum = addme(x, y);
    return 0;
}