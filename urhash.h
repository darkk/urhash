/* The MIT License

   Copyright (C) 2024 Leonid Evdokimov <leon@darkk.net.ru>

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without
   restriction, including without limitation the rights to use, copy,
   modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#ifndef URURU_URHASH_HDR_6BE8F3
#define URURU_URHASH_HDR_6BE8F3

#include <stdint.h>

#if defined(URHASH_H_AS_HDR) || defined(URHASH_H_AS_OBJ)
#   define URURU_LINK
#else
#   define URURU_LINK static inline
#endif

#ifdef URHASH_NO_TRICKERY
#   define URURU_TRICK
#elif defined(__mips__) && defined(__mips16) && !defined(__mips16e2) && (_MIPS_ISA == _MIPS_ISA_MIPS32 && __mips_isa_rev >= 2)
#   define URURU_TRICK __attribute__((nomips16))
#else
#   define URURU_TRICK
#endif

URURU_LINK URURU_TRICK
uint32_t urhash32(const uint32_t *buf, uint32_t bytelen, uint32_t seed);

#endif // URURU_URHASH_HDR_6BE8F3

/*************************************************************************************************/

#if !defined(URURU_URHASH_OBJ_9A7304) && (!defined(URHASH_H_AS_HDR) || defined(URHASH_H_AS_OBJ))
#define URURU_URHASH_OBJ_9A7304

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ && __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#   error PDP-Endian is not supported
#endif

#define URURU_ROTRV32(x, r) ((r) ? ((x) >> (r)) | ((x) << (32 - (r))) : (x))

/* Feedback like `v ^= prev_state` is not used as CFB breaks block indpendence
 * and it kinda makes the mixing quality dependent on input to a certain extent
 * and it's scary to me. However, it improves SMHasher metrics and comes for
 * ~free in terms of CPU cycles. */
URURU_LINK URURU_TRICK
uint32_t urhash32(const uint32_t *buf, const uint32_t bytelen, const uint32_t seed)
{
    const uint32_t weilzero = UINT32_C(0xEE5118A6),
                   weylstep = UINT32_C(0x9D4FAA83);
    const uint64_t m0 = UINT32_C(0xA52D526D),
                   m1 = UINT32_C(0x38B252B5),
                   m2 = UINT32_C(0x4A929775),
                   m3 = UINT32_C(0xA559BA65);
    // SMHasher's Keyset:Seed has ~22.25 bits, time_t(mod 8h) (s) ~14.8, (ms) ~24.8
    uint32_t s = seed;
    uint32_t weylseq = weilzero;
    for (const uint32_t *endroll= &buf[(bytelen >> 4) << 2]; buf != endroll; buf += 4)
    {
        uint64_t sacc = 0;
        sacc += m0 * (buf[0] ^ weylseq);
        sacc += m1 * (buf[1] ^ weylseq);
        sacc += m2 * (buf[2] ^ weylseq);
        sacc += m3 * (buf[3] ^ weylseq);
        const uint32_t hi = sacc >> 32, lo = sacc;
        s ^= (hi - lo);
        s = URURU_ROTRV32(s, weylseq & 0x1F);
        weylseq += weylstep;
    }
    do {
        const unsigned wordrem = (bytelen >> 2) & 3;
        uint64_t sacc = 0;
        switch (wordrem) {
            case 3: sacc += m3 * (*buf++ ^ weylseq); /* fallthrough */
            case 2: sacc += m1 * (*buf++ ^ weylseq); /* fallthrough */
            case 1: sacc += m2 * (*buf++ ^ weylseq); /* fallthrough */
        }
        // bytelen(DNS domain) has ~5.5 bits of entropy in the lower bits,
        // wordtail always ends with \x00 - let's match.
        const unsigned wordtail = bytelen & 3;
        // That's `<<3` and not `*8` due to funny GCC behavior. TODO: report it.
        sacc += m0 * (weylseq ^ bytelen ^ (wordtail ? (
            __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            ? *buf << (32 - (wordtail << 3))                // "\x11\x22\x33\x44" is 0x44332211
            : *buf & (UINT32_MAX << (32 - (wordtail << 3))) // "\x11\x22\x33\x44" is 0x11223344
        ) : 0));
        const uint32_t hi = sacc >> 32, lo = sacc;
        s ^= (hi - lo);
    } while (0);
    // prospector's lowbias32(~0.1076)
    s ^= s >> 16;
    s *= UINT32_C(0x21f0aaad);
    s ^= s >> 15;
    s *= UINT32_C(0xd35a2d97);
    s ^= s >> 15;
    return s;
}

#endif // URURU_URHASH_OBJ_9A7304
