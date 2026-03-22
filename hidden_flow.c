/*
 * FlagVault CTF -- "Hidden Flow"
 * Category: Reverse Engineering
 * Difficulty: Hard | Points: 450
 *
 * Validation logic is hidden behind:
 *   - A dispatch table of function pointers
 *   - Indirect calls via call [reg] / call rax
 *   - Multi-stage input checks
 *   - XOR-obfuscated flag storage (key 0x5F)
 *
 * Secret input: sp1d3r_w3b
 * Flag: FlagVault{1nd1r3ct_fl0w_m4st3r}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── XOR-obfuscated flag (key 0x5F) ──────────────────────────────────── */
static const uint8_t _FLAG[] = {
    0x19,0x33,0x3e,0x38,0x09,0x3e,0x2a,0x33,0x2b,0x24,
    0x6e,0x31,0x3b,0x6e,0x2d,0x6c,0x3c,0x2b,0x00,0x39,
    0x33,0x6f,0x28,0x00,0x32,0x6b,0x2c,0x2b,0x6c,0x2d,
    0x22
};
#define FLAG_LEN (sizeof(_FLAG)/sizeof(_FLAG[0]))

/* ── Toy rolling hash (intentionally obscure) ─────────────────────────── */
static uint32_t toy_hash(const char *s, size_t n) {
    uint32_t h = 0xCAFEBABEu;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)(unsigned char)s[i];
        h  = (h << 13) | (h >> 19);
        h += 0x9E3779B9u;
        h ^= h >> 7;
    }
    return h ^ 0x5A5A5A5Au;
}
static const uint32_t EXPECTED_HASH = 0x581d3018U;

/* ── Function pointer type ────────────────────────────────────────────── */
typedef int (*check_fn)(const char *, size_t);

/* ── Individual checks (hidden in dispatch table) ─────────────────────── */
static int chk_length(const char *s, size_t n) {
    return (n == 10) ? 0 : 1;
}

static int chk_has_digit(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s[i] >= '0' && s[i] <= '9') return 0;
    return 1;
}

static int chk_has_lower(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s[i] >= 'a' && s[i] <= 'z') return 0;
    return 1;
}

static int chk_has_underscore(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s[i] == '_') return 0;
    return 1;
}

static int chk_hash(const char *s, size_t n) {
    return (toy_hash(s, n) == EXPECTED_HASH) ? 0 : 1;
}

/* ── Dispatch table (what disassemblers show as a pointer array) ──────── */
static check_fn DISPATCH[] = {
    chk_length,
    chk_has_digit,
    chk_has_lower,
    chk_has_underscore,
    chk_hash,
};
#define N_CHECKS (sizeof(DISPATCH)/sizeof(DISPATCH[0]))

/* ── Indirect call trampoline ─────────────────────────────────────────── */
/* volatile forces: mov rax, [table+idx*8] ; call rax */
static int run_check(volatile check_fn *tbl, size_t idx, const char *s, size_t n) {
    volatile check_fn fn = tbl[idx];
    return fn(s, n);
}

/* ── Reveal flag ──────────────────────────────────────────────────────── */
static void reveal_flag(void) {
    char buf[FLAG_LEN + 1];
    for (size_t i = 0; i < FLAG_LEN; i++)
        buf[i] = (char)(_FLAG[i] ^ 0x5Fu);
    buf[FLAG_LEN] = '\0';
    printf("\n[+] Correct key! Flag: %s\n\n", buf);
}

/* ── Entry point ──────────────────────────────────────────────────────── */
int main(void) {
    char input[128];

    printf("\n[*] FlagVault CTF :: Hidden Flow\n");
    printf("[*] Enter the secret key: ");
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin)) {
        fprintf(stderr, "[-] Read error\n");
        return 1;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') input[--len] = '\0';

    int all_pass = 1;
    for (size_t i = 0; i < N_CHECKS; i++) {
        if (run_check((volatile check_fn *)DISPATCH, i, input, len) != 0) {
            all_pass = 0;
        }
    }

    if (all_pass) {
        reveal_flag();
    } else {
        printf("\n[-] Wrong key. Keep reversing.\n\n");
        return 1;
    }

    return 0;
}
