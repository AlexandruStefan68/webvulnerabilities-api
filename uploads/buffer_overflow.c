#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10]; // Buffer mic, de doar 10 octeți
    strcpy(buffer, input); // Nu verificăm dimensiunea inputului
    printf("Buffer content: %s\n", buffer);
}

int main() {
    char input[100] = "This input string is way too long and will cause a buffer overflow!";
    vulnerable_function(input); // Va cauza un buffer overflow
    return 0;
}
