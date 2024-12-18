#include <stdio.h>
#include <stdlib.h>

void double_free_example() {
    char *ptr = (char *)malloc(10 * sizeof(char)); // Alocăm memorie
    free(ptr); // Eliberăm memoria
    free(ptr); // Încercăm să eliberăm din nou aceeași memorie
}

int main() {
    double_free_example();
    return 0;
}
