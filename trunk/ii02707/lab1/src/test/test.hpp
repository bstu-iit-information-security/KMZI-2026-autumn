#pragma once

#include <gf256.hpp>
#include <belt.hpp>
#include <gcm.hpp>

#include <iostream>

struct TestStats {
    int passed = 0;
    int failed = 0;
};

void check(bool cond, const char* name, TestStats& s);
void section(const char* title);

template <size_t N>
bool bytes_equal(const uint8_t (&a)[N], const uint8_t (&b)[N]);
void fill_deterministic(uint8_t* buf, size_t len, uint32_t seed);
int count_bits(const uint8_t* a, const uint8_t* b, size_t len);

void test_gf256_algebra(TestStats& s);
void test_belt_properties(TestStats& s);
void test_rotl_rotr_constants(TestStats& s);
void test_gcm_boundary_lengths(TestStats& s);
void test_gcm_aad_independence(TestStats& s);
void test_gcm_forgery_rejected(TestStats& s);
void test_ct_compare(TestStats& s);
void test_gcm_nonzero_tag_always(TestStats& s);

void test_modulus_irreducibility(TestStats& s);

int run_all_extra_tests();