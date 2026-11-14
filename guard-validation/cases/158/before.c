/* Verbatim vulnerable mobi_decode_infl from libmobi commit
 * afa8ce1cd73429b5c37c9f6c55252f3329d38de8 (parent of the CVE-2022-1533 fix).
 *
 * Only the function name is suffixed with _before for side-by-side replay;
 * the body is byte-for-byte the upstream vulnerable implementation.
 *
 * Notable (vulnerable) bounds checks:
 *   - position-setting branch checks `pos < 0 || pos > *decoded_size`
 *   - insert branch:  `l < 0 || d + l > decoded + INDX_INFLBUF_SIZEMAX`
 *   - delete branch:  `l < 0 || d + l > decoded + INDX_INFLBUF_SIZEMAX`
 * The delete branch decrements pos when dir == '<' and never re-checks
 * pos >= 0, so pos can become negative and `decoded[pos]` is still read.
 */
MOBI_RET mobi_decode_infl_before(unsigned char *decoded, int *decoded_size, const unsigned char *rule) {
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
            if (pos < 0 || pos > *decoded_size) {
                debug_print("Position setting failed (%s)\n", decoded);
                return MOBI_DATA_CORRUPT;
            }
        }
        else {
            if (mod == 'i') {
                const unsigned char *s = decoded + pos;
                unsigned char *d = decoded + pos + 1;
                const int l = *decoded_size - pos;
                if (l < 0 || d + l > decoded + INDX_INFLBUF_SIZEMAX) {
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
                if (l < 0 || d + l > decoded + INDX_INFLBUF_SIZEMAX) {
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
