/* Local replay harness for CVE-2022-1533 (libmobi mobi_decode_infl).
 *
 * Compiles the verbatim vulnerable (before.c) and patched (after.c) copies
 * of the function and runs one variant per invocation with a crafted
 * `decoded` buffer guarded by a canary byte immediately before it.
 *
 * The byte decoded[-1] is a real byte of the backing allocation, so the
 * out-of-bounds read/write relative to `decoded` is observed via the canary
 * instead of crashing. This is a unit-level replay, not ASan and not a full
 * .mobi parse.
 *
 * Usage:
 *   mobi_decode_infl.exe <case_id> <variant:before|after> <decoded_ascii> \
 *                        <canary_dec> <rule_hex>
 *
 * stdout carries one machine-readable summary line; stderr carries the
 * upstream debug_print messages (the evidence of pos and the access).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define INDX_INFLBUF_SIZEMAX 500

typedef enum {
    MOBI_SUCCESS = 0,
    MOBI_DATA_CORRUPT = 1,
    MOBI_PARAM_ERR = 2,
    MOBI_INIT_FAILED = 3,
    MOBI_MALLOC_FAILED = 4
} MOBI_RET;

static void debug_print(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#include "before.c"
#include "after.c"

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s <case_id> <variant> <decoded_ascii> <canary_dec> <rule_hex>\n", argv[0]);
        return 2;
    }
    const char *case_id = argv[1];
    const char *variant = argv[2];
    const char *decoded_ascii = argv[3];
    int canary = atoi(argv[4]);
    const char *rule_hex = argv[5];

    MOBI_RET (*fn)(unsigned char *, int *, const unsigned char *) = NULL;
    if (strcmp(variant, "before") == 0) fn = mobi_decode_infl_before;
    else if (strcmp(variant, "after") == 0) fn = mobi_decode_infl_after;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    size_t dlen = strlen(decoded_ascii);
    size_t rlen = strlen(rule_hex) / 2;
    unsigned char rule[512];
    for (size_t i = 0; i < rlen; i++) {
        int hi = hexval(rule_hex[2 * i]);
        int lo = hexval(rule_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad rule hex: %s\n", rule_hex); return 2; }
        rule[i] = (unsigned char)((hi << 4) | lo);
    }
    rule[rlen] = 0;

    unsigned char backing[INDX_INFLBUF_SIZEMAX + 3];
    memset(backing, 0, sizeof backing);
    unsigned char *decoded = backing + 1;   /* decoded[-1] == backing[0] (canary) */
    memcpy(decoded, decoded_ascii, dlen);
    decoded[dlen] = 0;
    backing[0] = (unsigned char) canary;
    int decoded_size = (int) dlen;

    fprintf(stderr, "[%s/%s] call: decoded='%s' size=%d canary=0x%02x rule=0x",
            case_id, variant, decoded, decoded_size, backing[0]);
    for (size_t i = 0; i < rlen; i++) fprintf(stderr, "%02x", rule[i]);
    fprintf(stderr, "\n");

    MOBI_RET ret = fn(decoded, &decoded_size, rule);

    fprintf(stdout,
            "CASE=%s VARIANT=%s RET=%d DECODED_SIZE=%d CANARY_BEFORE=%d CANARY_AFTER=%d DECODED0=%d\n",
            case_id, variant, (int) ret, decoded_size, canary, backing[0], decoded[0]);
    return 0;
}
