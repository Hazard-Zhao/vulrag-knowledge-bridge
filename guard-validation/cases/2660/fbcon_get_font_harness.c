/* Local replay harness for CVE-2020-28915 (fbcon_get_font).
 *
 * Compiles the verbatim vulnerable (before.c), patched (after.c) and derived
 * ineffective (ineffective.c) / equivalent (equivalent.c) copies and runs one
 * <variant, hi_font> combination per invocation.
 *
 * The out-of-bounds access under test is a READ past the fontdata buffer:
 * the copy loop advances `fontdata += j` for `charcount` iterations, reading
 * `charcount * j` bytes total. When `charcount * j > FNTSIZE(fontdata)` (hi
 * font: 512 chars x 16 bytes = 8192 > 4096) the loop reads past the buffer.
 *
 * The harness backs `fontdata` with a 0x11-filled buffer followed by an
 * 0xAA canary region, and a fresh 0x00 output buffer; an OOB read is observed
 * as 0xAA bytes appearing in the output `font->data`. No ASan required.
 *
 * FNTSIZE is stubbed to the harness buffer size (4096) for the unit replay;
 * the real kernel computes it from the font header (CID-6735b4632def).
 *
 * Usage:
 *   fbcon_get_font_harness.exe <variant:before|after|ineffective-01|equivalent-01> <hi_font:0|1>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define EINVAL 22
#define FNTSIZE(fontdata) (4096)
#define FONTDATA_SIZE 4096
#define CANARY_SIZE 8192
#define MAX_OUT (512 * 32)

struct vc_data {
    struct { u8 *data; int width, height; } vc_font;
    int vc_hi_font_mask;
};
struct console_font {
    u8 *data;
    int width, height, charcount;
};

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <hi_font:0|1>\n", argv[0]);
        return 2;
    }
    const char *variant = argv[1];
    int hi_font = atoi(argv[2]);

    int (*fn)(struct vc_data *, struct console_font *) = NULL;
    if (strcmp(variant, "before") == 0) fn = fbcon_get_font_before;
    else if (strcmp(variant, "after") == 0) fn = fbcon_get_font_after;
    else if (strcmp(variant, "ineffective-01") == 0) fn = fbcon_get_font_ineffective;
    else if (strcmp(variant, "equivalent-01") == 0) fn = fbcon_get_font_equivalent;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    static u8 fontdata[FONTDATA_SIZE + CANARY_SIZE];
    static u8 out[MAX_OUT];
    memset(fontdata, 0x11, FONTDATA_SIZE);
    memset(fontdata + FONTDATA_SIZE, 0xAA, CANARY_SIZE);
    memset(out, 0x00, MAX_OUT);

    struct vc_data vc;
    struct console_font font;
    vc.vc_font.data = fontdata;
    vc.vc_font.width = 8;      /* first branch: j = height */
    vc.vc_font.height = 16;    /* j = 16 bytes per glyph */
    vc.vc_hi_font_mask = hi_font;
    font.data = out;
    font.width = font.height = font.charcount = 0;

    int ret = fn(&vc, &font);

    int charcount = font.charcount;
    int oob_read = 0;
    for (int k = 0; k < charcount * 32; k++) {
        if (out[k] == 0xAA) { oob_read = 1; break; }
    }
    int canary_intact = (fontdata[FONTDATA_SIZE] == 0xAA) ? 1 : 0;

    fprintf(stderr,
            "[%s/hi_font=%d] charcount=%d ret=%d oob_read=%d canary_intact=%d\n",
            variant, hi_font, charcount, ret, oob_read, canary_intact);

    fprintf(stdout,
            "VARIANT=%s HI_FONT=%d CHARCOUNT=%d RET=%d OOB_READ=%d CANARY_INTACT=%d\n",
            variant, hi_font, charcount, ret, oob_read, canary_intact);
    return 0;
}
