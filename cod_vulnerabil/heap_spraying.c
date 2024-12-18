#include <stdio.h>
#include <stdlib.h>

void heap_spraying_example() {
    char *ptr;
    for (int i = 0; i < 1000; i++) { // Creăm multiple alocări pe heap
        ptr = (char *)malloc(100); // Alocăm câte 100 de octeți
        if (ptr != NULL) {
            memset(ptr, 'A', 99); // Umplem memoria cu date controlate
            ptr[99] = '\0'; // Terminator de șir
        }
    }
    printf("Heap spraying complete.\n");
}

int main() {
    heap_spraying_example();
    return 0;
}
