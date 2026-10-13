#include <iostream>

#include <demo.hpp>
#include <test.hpp>

int main() {
    const int demo_rc = crypto::demo::run_demo();
    if (demo_rc != 0) {
        std::cerr << "[!] Демонстрация завершилась с ошибкой.\n";
        return demo_rc;
    }

    return run_all_extra_tests();
}