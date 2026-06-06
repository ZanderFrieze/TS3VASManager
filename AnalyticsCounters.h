#pragma once
#include <atomic>

struct CounterData {
    std::atomic<long long> value;
};