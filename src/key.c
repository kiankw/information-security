#include "key.h"

#include <time.h>
/*
p, q, n, phi, e=65537, d
*/
void gene_prime(mpz_t n, int len, gmp_randstate_t state);
int pq_isValid(mpz_t p, mpz_t q, int k);

void gene_n(mpz_t p, mpz_t q);
void gene_e(void);
void gene_d(mpz_t p, mpz_t q);

void initKey(int k) {
	mpz_init(n);
	mpz_init(e);
	mpz_init(d);

	static gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

	do {
		mpz_t p; mpz_init(p);
		mpz_t q; mpz_init(q);
		
		do {
			gene_prime(p, k / 2, state);
			gene_prime(q, k / 2, state);
		} while (!pq_isValid(p, q, k));

		gene_n(p, q);
		gene_e();
		gene_d(p, q);
	} while (mpz_sizeinbase(n, 2) != k);
	return ;
}

void gene_prime(mpz_t n, int len, gmp_randstate_t state) {
	mpz_rrandomb(n, state, len);
	mpz_nextprime(n, n);
}

int pq_isValid(mpz_t p, mpz_t q, int k) {
    mpz_t t; mpz_init(t);
    mpz_sub(t, p, q);
    mpz_abs(t, t);

    // log|p - q|> k/2-100
	mpz_t t1; mpz_init(t1);
	int e1 = k / 2 - 100;
	mpz_t b1; mpz_init(b1); mpz_set_ui(b1, 2);
	mpz_pow_ui(t1, b1, e1);
	if (mpz_cmp(t, t1) <= 0) return 0;

	// log|p - q|> k/3
	mpz_t t2; mpz_init(t2);
	int e2 = k / 3;
	mpz_t b2; mpz_init(b2); mpz_set_ui(b2, 2);
	mpz_pow_ui(t2, b2, e2);
	if (mpz_cmp(t, t2) <= 0) return 0;

	mpz_clear(t);
	mpz_clear(t1);
	mpz_clear(b1);
	mpz_clear(t2);
	mpz_clear(b2);
	return 1;
}

void gene_n(mpz_t p, mpz_t q) {
    mpz_mul(n, p, q);
	return ;
}
void gene_e(void) {
	mpz_set_ui(e, 65537);
    return ;
}

void gcdEx(mpz_t ans, mpz_t a, mpz_t b, mpz_t x, mpz_t y) {
    mpz_t ta; mpz_init(ta);
    mpz_t tb; mpz_init(tb);
    mpz_set(ta, a);
    mpz_set(tb, b);

    if (mpz_cmp_ui(tb, 0) == 0) {
        mpz_set_ui(x, 1);
        mpz_set_ui(y, 0);
        mpz_set(ans, ta);
    } else {
        mpz_t r; mpz_init(r);
        mpz_t t; mpz_init(t);

        mpz_fdiv_r(t, a, b);
        gcdEx(b, t, x, y, r);
        mpz_set(ans, r);

        mpz_set(t, x);
        mpz_set(x, y);

        mpz_fdiv_q(r, a, b);
        mpz_mul(r, r, y);
        mpz_sub(y, t, r);

        mpz_clear(t);
        mpz_clear(r);
    }

    mpz_clear(tb);
    mpz_clear(ta);
    return ;
}
void mod_reverse(mpz_t e, mpz_t phi) {
    mpz_t x; mpz_init(x);
    mpz_t y; mpz_init(y);

    gcdEx(d, e, phi, x, y);
    if (mpz_cmp_ui(d, 1) == 0) {
        mpz_fdiv_r(d, x, phi);
        mpz_add(d, d, phi);
        mpz_fdiv_r(d, d, phi);
    }

	mpz_clear(y);
	mpz_clear(x);
	return ;
}

void gene_d(mpz_t p, mpz_t q) {
    mpz_t phi; mpz_init(phi);

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);
#if 0
    mod_reverse(e, phi);
#else
	mpz_invert(d, e, phi);
#endif

	mpz_clear(phi);
	return ;
}

