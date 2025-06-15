/*
ssl_interceptor

A simple SSL/TLS interceptor for debugging purposes.

Usage:
$ gcc -shared -fPIC ssl_interceptor.c -o ssl_interceptor.so -ldl
$ mv ./ssl_interceptor.so /usr/local/lib/
$ sudo systemctl edit aTrustDaemon.service
[Service]
Environment="LD_PRELOAD=/usr/local/lib/ssl_interceptor.so"
$ systemctl kill -s SIGKILL aTrustDaemon.service
$ echo '' > /var/log/ssl_intercept.log

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define LOG_FILE_PATH "/var/log/ssl_intercept.log"
static FILE *log_file = NULL;

static int (*original_SSL_read)(SSL *ssl, void *buf, int num) = NULL;
static int (*original_SSL_write)(SSL *ssl, const void *buf, int num) = NULL;

__attribute__((constructor)) void interceptor_init(void)
{
    log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL)
    {
        perror("INTERCEPTOR: Failed to open log file");
        return;
    }
}

__attribute__((destructor)) void interceptor_fini(void)
{
    if (log_file != NULL)
    {
        fclose(log_file);
        log_file = NULL;
    }
}

void hex_dump_to_file(const char *title, const void *data, int size)
{
    if (log_file == NULL)
        return;

    const unsigned char *p = (const unsigned char *)data;
    fprintf(log_file, "[%d] %s %d bytes\n", getpid(), title, size);

    if (size <= 0)
    {
        fprintf(log_file, "  (empty)\n");
        return;
    }

    for (int i = 0; i < size; i += 16)
    {
        fprintf(log_file, "  %04x: ", i);
        for (int j = 0; j < 16; j++)
        {
            if (i + j < size)
                fprintf(log_file, "%02x ", p[i + j]);
            else
                fprintf(log_file, "   ");
        }
        fprintf(log_file, " ");
        for (int j = 0; j < 16; j++)
        {
            if (i + j < size)
                fprintf(log_file, "%c", isprint(p[i + j]) ? p[i + j] : '.');
        }
        fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");
    fflush(log_file);
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    if (!original_SSL_write)
    {
        original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    }

    if (log_file != NULL)
    {
        hex_dump_to_file("SSL_write", buf, num);
    }

    if (!original_SSL_write)
        return -1;

    int result = original_SSL_write(ssl, buf, num);

    // if (log_file != NULL) {
    //     fprintf(log_file, "[%d] SSL_write return %d\n\n", getpid(), result);
    //     fflush(log_file);
    // }

    return result;
}

int SSL_read(SSL *ssl, void *buf, int num)
{
    if (!original_SSL_read)
    {
        original_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    }

    if (!original_SSL_read)
        return -1;

    int result = original_SSL_read(ssl, buf, num);

    if (log_file != NULL && result > 0)
    {
        hex_dump_to_file("SSL_read", buf, result);
    }

    // if (log_file != NULL) {
    //     fprintf(log_file, "[%d] SSL_read return %d\n\n", getpid(), result);
    //     fflush(log_file);
    // }

    return result;
}