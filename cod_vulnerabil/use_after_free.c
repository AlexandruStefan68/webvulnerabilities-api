#include <stdio.h>
#include <stdlib.h>

void use_after_free_example() {
    char *ptr = (char *)malloc(10 * sizeof(char)); // Alocăm memorie
    free(ptr); // Eliberăm memoria
    printf("Accessing freed memory: %s\n", ptr); // Accesăm memoria deja eliberată
}

int main() {
    use_after_free_example();
    return 0;
}
