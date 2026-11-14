/* Verbatim patched mobi_decode_infl from libmobi commit
 * eafc415bc6067e72577f70d6dd5acbf057ce6e6f (the CVE-2022-1533 fix).
 *
 * Only the function name is suffixed with _after for side-by-side replay;
 * the body is byte-for-byte the upstream patched implementation.
 *
 * Changes versus the vulnerable version:
 *   - position-setting branch check removed
 *   - insert branch adds `pos < 0`
 *   - delete branch adds `pos < 0` and changes the upper-bound check from
 *     `d + l` to `s + l`
 * The delete branch now returns MOBI_DATA_CORRUPT before ever reading
 * `decoded[pos]` when pos has gone negative.
 */
MOBI_RET mobi_decode_infl_after(unsigned char *decoded, int *decoded_size, const unsigned char *rule) {
    int pos = *decoded_size;
    char mod = 'i';
    char dir = '<';
    char olddir;
    unsigned char c;
    while ((c = *rule++)) {
        if (c <= 4) {
            mod = (c <= 2) ? 'i' : 'd'; /* insert, delete */
            olddir = dir;
            dir = (c & 2) ? '<' : '>'; /* left, right */
            if (olddir != dir && olddir) {
                pos = (c & 2) ? *decoded_size : 0;
            }
        }
        else if (c > 10 && c < 20) {
            if (dir == '>') {
                pos = *decoded_size;
            }
            pos -= c - 10;
            dir = 0;
        }
        else {
            if (mod == 'i') {
                const unsigned char *s = decoded + pos;
                unsigned char *d = decoded + pos + 1;
                const int l = *decoded_size - pos;
                if (pos < 0 || l < 0 || d + l > decoded + INDX_INFLBUF_SIZEMAX) {
                    debug_print("Out of buffer in %s at pos: %i\n", decoded, pos);
                    return MOBI_DATA_CORRUPT;
                }
                memmove(d, s, (size_t) l);
                decoded[pos] = c;
                (*decoded_size)++;
                if (dir == '>') { pos++; }
            } else {
                if (dir == '<') { pos--; }
                const unsigned char *s = decoded + pos + 1;
                unsigned char *d = decoded + pos;
                const int l = *decoded_size - pos;
                if (pos < 0 || l < 0 || s + l > decoded + INDX_INFLBUF_SIZEMAX) {
                    debug_print("Out of buffer in %s at pos: %i\n", decoded, pos);
                    return MOBI_DATA_CORRUPT;
                }
                if (decoded[pos] != c) {
                    debug_print("Character mismatch in %s at pos: %i (%c != %c)\n", decoded, pos, decoded[pos], c);
                    return MOBI_DATA_CORRUPT;
                }
                memmove(d, s, (size_t) l);
                (*decoded_size)--;
            }
        }
    }
    return MOBI_SUCCESS;
}
