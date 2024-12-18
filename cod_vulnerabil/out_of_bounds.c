#include <stdio.h>

void out_of_bounds_example() {
    int buffer[5] = {1, 2, 3, 4, 5};
    printf("Accessing out-of-bounds element: %d\n", buffer[10]); // Accesăm un element dincolo de limite
}

int main() {
    out_of_bounds_example();
    return 0;
}
