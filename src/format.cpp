#include "format.h"

#include <chrono>
#include <iomanip>
#include <string>

using std::string;

// INPUT: Long int measuring seconds
// OUTPUT: HH:MM:SS
// REMOVE: [[maybe_unused]] once you define the function
string Format::ElapsedTime(long seconds) {
  // REMARK: This implementation is done based on the code review that I
  // received from the udacity reviewer
  std::chrono::seconds secs{seconds};
  std::chrono::hours hours =
      std::chrono::duration_cast<std::chrono::hours>(secs);

  secs -= std::chrono::duration_cast<std::chrono::seconds>(hours);

  std::chrono::minutes mins =
      std::chrono::duration_cast<std::chrono::minutes>(secs);

  secs -= std::chrono::duration_cast<std::chrono::seconds>(mins);

  std::stringstream strstream{};

  strstream << std::setw(2) << std::setfill('0') << hours.count()
            << std::setw(1) << ":" << std::setw(2) << std::setfill('0')
            << mins.count() << std::setw(1) << ":" << std::setw(2)
            << std::setfill('0') << secs.count();

  return strstream.str();
}