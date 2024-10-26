#include <cstdio>
#include <unistd.h>
#include <iostream>

size_t testFun(int n, const char *s) {
    printf("Number: %d, str = %s\n", n, s);
    return strlen(s);
}

int fun1() {
    int i = 1;
    const char *str = "Test Str!";
    printf("testFun() address is at %p\n", testFun);
    printf("str address is at %p\n", str);
    while (i < 1 * 1000 * 1000) {
        size_t returnValue = testFun(i++, str);
        printf("returnValue=%zu\n", returnValue);
        sleep(1);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    std::cout << "Hello, World, Kai!" << std::endl;
    return fun1();
}
