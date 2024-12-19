#ifndef TIMING_H
#define TIMING_H

#include <chrono>
#include <cstddef>
#include "server.h"

struct TimingInfo
{
    std::chrono::high_resolution_clock::time_point start;
    std::chrono::high_resolution_clock::time_point end;
};

void start_timing(TimingInfo &timing);
void end_timing(TimingInfo &timing);
void log_throughput(quill::Logger *logger, size_t total_bytes, const TimingInfo &timing);

#endif // TIMING_H
