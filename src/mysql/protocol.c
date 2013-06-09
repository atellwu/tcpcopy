
#include <xcopy.h>
#include "pairs.h"
#include "protocol.h"

static inline unsigned char
char_val(unsigned char X)
{
    return (unsigned char) (X >= '0' && X <= '9' ? X-'0':
            X >= 'A' && X <= 'Z' ? X - 'A' + 10 : X - 'a' + 10);
}

static void
new_hash(uint64_t *result, const char *password)
{
    int        i = 0, length;
    uint64_t   nr  = 1345345333L, add = 7, nr2 = 0x12345671L, tmp;

    length = strlen(password);

    for (; i < length; ++i) {
        if (' ' == password[i] || '\t' == password[i]) {
            /* skip spaces */
            continue;
        }

        tmp  = (0xff & password[i]);
        nr  ^= ((((nr & 63) + add) * tmp) + (nr << 8));
        nr2 += ((nr2 << 8) ^ nr);
        add += tmp;
    }

    result[0] = nr & 0x7fffffffL;
    result[1] = nr2 & 0x7fffffffL;

}

/*
 * right from Monty's code
 */
void
new_crypt(char *result, const char *password, char *message)
{
    int      length, i;
    char     b;
    double   d;
    uint64_t pw[2], msg[2], max, seed1, seed2;

    new_hash(pw, message);
    new_hash(msg, password);

    max = 0x3fffffffL;
    seed1 = (pw[0] ^ msg[0]) % max;
    seed2 = (pw[1] ^ msg[1]) % max;
    length = strlen(message);

    for (i =0; i < length; i++) {
        seed1 = ((seed1 * 3) + seed2) % max;
        seed2 = (seed1 + seed2 + 33) % max;
        d = (double) seed1 / (double) max;
        b = (char)floor((d * 31) + 64);
        result[i] = b;
    }

    seed1 = ((seed1 * 3) + seed2) % max;

    d = (double) seed1 / (double) max;
    b = (char) floor(d * 31);

    for (i = 0; i < length; i++) {
        result[i] ^= (char) b;
    }
}

int
is_last_data_packet(unsigned char *payload)
{
    size_t         len;
    unsigned char *p;

    p   = payload;
    len = p[0] + (p[1] << 8) + (p[2] << 16);

    if (len < 9) {
        /* skip packet length */
        p = p + 3;
        /* skip packet number */
        p = p + 1;
        if (254 == p[0]) {
            return 1;
        }
    }
    return 0;
}

