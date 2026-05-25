/*
 * Lab 2 — Buffer Overflow
 * Task: Vulnerable TCP server (Level 1 target)
 * Description:
 *   A deliberately vulnerable C program that accepts a TCP connection on
 *   port 9090, reads data from the client, and copies it into a fixed-size
 *   stack buffer using the unsafe strcpy() function.  No bounds checking is
 *   performed, making it exploitable via a stack-based buffer overflow.
 *
 * Compile:
 *   gcc -DBOF -z execstack -fno-stack-protector -m32 -o stack-L1 stack.c
 *
 *   Flags explained:
 *     -DBOF              : Enable the vulnerable bof() code path
 *     -z execstack       : Make the stack executable (needed for shellcode)
 *     -fno-stack-protector: Disable stack canaries (SSP)
 *     -m32               : Compile as 32-bit binary so addresses fit in 4 bytes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT     9090
#define BUFSIZE  200    /* Intentionally small — overflow target */

/* --------------------------------------------------------------------------
 * bof() — the vulnerable function
 * --------------------------------------------------------------------------
 * The local array 'buffer' is allocated on the stack with BUFSIZE bytes.
 * strcpy() copies the caller-supplied string without checking length.
 * If the input is longer than 200 bytes it overwrites:
 *   1. The saved frame pointer (ebp) stored just above the buffer
 *   2. The saved return address stored above ebp
 * Overwriting the return address with an attacker-controlled value redirects
 * execution when bof() returns.
 */
void bof(char *str)
{
    char buffer[BUFSIZE];   /* 200-byte stack buffer — the overflow target */

    /* Print the addresses the attacker needs for crafting the payload */
    printf("Buffer's address inside bof():  0x%x\n", (unsigned int)(uintptr_t) buffer);
    printf("Frame Pointer (ebp) inside bof():  0x%x\n", (unsigned int)(uintptr_t) __builtin_frame_address(0));

    /* VULNERABLE: strcpy does not check that strlen(str) <= BUFSIZE */
    strcpy(buffer, str);    /* <-- overflow happens here */

    return;
}

/* --------------------------------------------------------------------------
 * dummy_function() — not exploited but present to add stack frame complexity
 * -------------------------------------------------------------------------- */
void dummy_function(char *str)
{
    char dummy_buffer[1000]; /* Large buffer so the stack frame is predictable */
    memset(dummy_buffer, 0, sizeof(dummy_buffer));
    bof(str);
}

/* --------------------------------------------------------------------------
 * main() — TCP server
 * -------------------------------------------------------------------------- */
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char input[2000];   /* Buffer for reading from the socket (larger than bof's buffer) */
    ssize_t n;

    /* Create a TCP socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Allow address reuse so we can restart quickly after a crash */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to all interfaces on PORT */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* Listen for one connection at a time */
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("[*] Stack server listening on port %d ...\n", PORT);
    fflush(stdout);

    /* Main accept loop */
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        printf("[*] Connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        /* Read the attacker's payload */
        memset(input, 0, sizeof(input));
        n = read(client_fd, input, sizeof(input) - 1);
        if (n < 0) {
            perror("read");
            close(client_fd);
            continue;
        }
        input[n] = '\0';

        /* Trigger the overflow */
        dummy_function(input);

        /* This message is only reached if the return address was NOT overwritten
         * to redirect to shellcode (i.e., the exploit did not work) */
        printf("[-] Returned properly — exploit did not succeed.\n");

        close(client_fd);
    }

    /* Never reached in normal operation */
    close(server_fd);
    return 0;
}
