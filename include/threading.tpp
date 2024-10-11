#ifndef THREADING_TPP
#define THREADING_TPP

#include <functional>
#include <future>
#include "logger.h"

template <typename Func, typename... Args>
void threaded(quill::Logger *logger, int retry_delay_sec, int max_retries, Func func, Args &&...args)
{
    int attempts = 0;
    while (attempts < max_retries)
    {
        try
        {
            func(std::forward<Args>(args)...);
            // LOG_INFO(logger, "Operation succeeded.");
            return; // Success
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(logger, "Caught exception on attempt {}: {}", attempts + 1, e.what());
            if (attempts + 1 >= max_retries)
            {
                LOG_ERROR(logger, "Max retries reached. Giving up.");
                break; // Give up after max_retries
            }
            LOG_INFO(logger, "Retrying in {} seconds...", retry_delay_sec);
            std::this_thread::sleep_for(std::chrono::seconds(retry_delay_sec));
            attempts++;
            retry_delay_sec *= 2; // Exponential backoff
        }
        catch (...)
        {
            LOG_ERROR(logger, "Caught unknown exception on attempt {}", attempts + 1);
            if (attempts + 1 >= max_retries)
            {
                LOG_ERROR(logger, "Max retries reached with unknown error. Giving up.");
                break;
            }
            LOG_INFO(logger, "Retrying in {} seconds...", retry_delay_sec);
            std::this_thread::sleep_for(std::chrono::seconds(retry_delay_sec));
            attempts++;
            retry_delay_sec *= 2; // Exponential backoff
        }
    }
}

#endif // THREADING_TPP