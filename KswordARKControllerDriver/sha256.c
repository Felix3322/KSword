#include "controller.h"

typedef struct _KSCC_SHA256_CONTEXT {
    ULONG State[8];
    ULONGLONG TotalBytes;
    UCHAR Block[64];
    ULONG BlockBytes;
} KSCC_SHA256_CONTEXT;

/* SHA-256 round constants defined by FIPS 180-4. */
static const ULONG g_KsccSha256K[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

/* Rotate a 32-bit word right by a compile-time-sized count. */
static ULONG
KsccRotateRight(
    _In_ ULONG Value,
    _In_ ULONG Count)
{
    return (Value >> Count) | (Value << (32U - Count));
}

/* Compress one 512-bit block into the eight-word SHA-256 state. */
static VOID
KsccSha256Transform(
    _Inout_ KSCC_SHA256_CONTEXT* Context,
    _In_reads_(64) const UCHAR* Block)
{
    ULONG words[64];
    ULONG index;
    ULONG a;
    ULONG b;
    ULONG c;
    ULONG d;
    ULONG e;
    ULONG f;
    ULONG g;
    ULONG h;

    for (index = 0U; index < 16U; ++index) {
        words[index] =
            ((ULONG)Block[index * 4U] << 24U) |
            ((ULONG)Block[index * 4U + 1U] << 16U) |
            ((ULONG)Block[index * 4U + 2U] << 8U) |
            Block[index * 4U + 3U];
    }
    for (index = 16U; index < 64U; ++index) {
        ULONG s0;
        ULONG s1;

        s0 =
            KsccRotateRight(words[index - 15U], 7U) ^
            KsccRotateRight(words[index - 15U], 18U) ^
            (words[index - 15U] >> 3U);
        s1 =
            KsccRotateRight(words[index - 2U], 17U) ^
            KsccRotateRight(words[index - 2U], 19U) ^
            (words[index - 2U] >> 10U);
        words[index] =
            words[index - 16U] +
            s0 +
            words[index - 7U] +
            s1;
    }

    a = Context->State[0];
    b = Context->State[1];
    c = Context->State[2];
    d = Context->State[3];
    e = Context->State[4];
    f = Context->State[5];
    g = Context->State[6];
    h = Context->State[7];
    for (index = 0U; index < 64U; ++index) {
        ULONG sigma1;
        ULONG choice;
        ULONG temporary1;
        ULONG sigma0;
        ULONG majority;
        ULONG temporary2;

        sigma1 =
            KsccRotateRight(e, 6U) ^
            KsccRotateRight(e, 11U) ^
            KsccRotateRight(e, 25U);
        choice = (e & f) ^ ((~e) & g);
        temporary1 =
            h +
            sigma1 +
            choice +
            g_KsccSha256K[index] +
            words[index];
        sigma0 =
            KsccRotateRight(a, 2U) ^
            KsccRotateRight(a, 13U) ^
            KsccRotateRight(a, 22U);
        majority = (a & b) ^ (a & c) ^ (b & c);
        temporary2 = sigma0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    Context->State[0] += a;
    Context->State[1] += b;
    Context->State[2] += c;
    Context->State[3] += d;
    Context->State[4] += e;
    Context->State[5] += f;
    Context->State[6] += g;
    Context->State[7] += h;
}

/* Initialize SHA-256 with its standard initial hash value. */
static VOID
KsccSha256Initialize(
    _Out_ KSCC_SHA256_CONTEXT* Context)
{
    RtlZeroMemory(Context, sizeof(*Context));
    Context->State[0] = 0x6A09E667U;
    Context->State[1] = 0xBB67AE85U;
    Context->State[2] = 0x3C6EF372U;
    Context->State[3] = 0xA54FF53AU;
    Context->State[4] = 0x510E527FU;
    Context->State[5] = 0x9B05688CU;
    Context->State[6] = 0x1F83D9ABU;
    Context->State[7] = 0x5BE0CD19U;
}

/* Feed an arbitrary byte sequence into the SHA-256 block accumulator. */
static VOID
KsccSha256Update(
    _Inout_ KSCC_SHA256_CONTEXT* Context,
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ SIZE_T Length)
{
    SIZE_T consumed;

    consumed = 0U;
    Context->TotalBytes += Length;
    while (consumed < Length) {
        SIZE_T remaining;
        SIZE_T copyBytes;

        remaining = Length - consumed;
        copyBytes = 64U - Context->BlockBytes;
        if (copyBytes > remaining) {
            copyBytes = remaining;
        }
        RtlCopyMemory(
            Context->Block + Context->BlockBytes,
            Data + consumed,
            copyBytes);
        Context->BlockBytes += (ULONG)copyBytes;
        consumed += copyBytes;
        if (Context->BlockBytes == 64U) {
            KsccSha256Transform(Context, Context->Block);
            Context->BlockBytes = 0U;
        }
    }
}

/* Add FIPS padding and serialize the final state in network byte order. */
static VOID
KsccSha256Finalize(
    _Inout_ KSCC_SHA256_CONTEXT* Context,
    _Out_writes_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) UCHAR* Digest)
{
    ULONGLONG bitLength;
    ULONG index;

    bitLength = Context->TotalBytes * 8ULL;
    Context->Block[Context->BlockBytes++] = 0x80U;
    if (Context->BlockBytes > 56U) {
        while (Context->BlockBytes < 64U) {
            Context->Block[Context->BlockBytes++] = 0U;
        }
        KsccSha256Transform(Context, Context->Block);
        Context->BlockBytes = 0U;
    }
    while (Context->BlockBytes < 56U) {
        Context->Block[Context->BlockBytes++] = 0U;
    }
    for (index = 0U; index < 8U; ++index) {
        Context->Block[63U - index] = (UCHAR)(bitLength >> (index * 8U));
    }
    KsccSha256Transform(Context, Context->Block);
    for (index = 0U; index < 8U; ++index) {
        Digest[index * 4U] = (UCHAR)(Context->State[index] >> 24U);
        Digest[index * 4U + 1U] = (UCHAR)(Context->State[index] >> 16U);
        Digest[index * 4U + 2U] = (UCHAR)(Context->State[index] >> 8U);
        Digest[index * 4U + 3U] = (UCHAR)Context->State[index];
    }
}

/* Compute SHA-256 for a complete in-memory buffer. */
VOID
KsccSha256(
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ SIZE_T Length,
    _Out_writes_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) UCHAR* Digest)
{
    KSCC_SHA256_CONTEXT context;

    KsccSha256Initialize(&context);
    KsccSha256Update(&context, Data, Length);
    KsccSha256Finalize(&context, Digest);
    RtlSecureZeroMemory(&context, sizeof(context));
}
