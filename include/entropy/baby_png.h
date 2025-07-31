/// Last modified at 2025年07月31日 星期四 16时34分59秒
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <fcntl.h>
    #include <errno.h>
#endif // windows check

#ifdef __linux__
    #include <unistd.h>
    #define _GNU_SOURCE
    #include <sys/syscall.h>
#endif // linux check

#ifndef __BABY_PRG_H__
#define __BABY_PRG_H__

void randombytes(uint8_t *out, size_t outlen);


#endif // BABY_PRG_H
