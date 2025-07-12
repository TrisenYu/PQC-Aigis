/// Last modified at 2025年07月12日 星期六 14时46分59秒
#include <stdlib.h>

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

#if defined(_WIN32) || defined(_WIN64)
    void randombytes(uint8_t *out, size_t outlen) {
        HCRYPTPROV ctx;
        DWORD len;
        if(!CryptAcquireContext(
            &ctx, NULL, NULL, 
            PROV_RSA_FULL, 
            CRYPT_VERIFYCONTEXT)
        ) {
            abort();
        }

        while(outlen > 0) {
            len = (outlen > 1048576) ? 1048576 : outlen;
            if(!CryptGenRandom(ctx, len, (BYTE *)out)) {
                abort();
            }
            out += len;
            outlen -= len;
        }

        if(!CryptReleaseContext(ctx, 0))
            abort();
    }
#elif defined (__linux__) && defined(SYS_getrandom)
    void randombytes(uint8_t *out, size_t outlen) {
        ssize_t ret;

        while(outlen > 0) {
            ret = syscall(SYS_getrandom, out, outlen, 0);
            if(ret == -1 && errno == EINTR)
                continue;
            else if(ret == -1)
                abort();

            out += ret;
            outlen -= ret;
        }
    }
#else
    void randombytes(uint8_t *out, size_t outlen) {
        static int fd = -1;
        ssize_t ret;

        while(fd == -1) {
            fd = open("/dev/urandom", O_RDONLY);
            if(fd == -1 && errno == EINTR)
                continue;
            else if(fd == -1)
                abort();
        }

        while(outlen > 0) {
            ret = read(fd, out, outlen);
            if(ret == -1 && errno == EINTR)
                continue;
            else if(ret == -1)
                abort();

            out += ret;
            outlen -= ret;
        }
    }
#endif // define check

#endif // BABY_PRG_H
