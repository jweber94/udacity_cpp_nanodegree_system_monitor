#include <string>

#include "format.h"

using std::string;

// TODO: Complete this helper function
// INPUT: Long int measuring seconds
// OUTPUT: HH:MM:SS
// REMOVE: [[maybe_unused]] once you define the function
string Format::ElapsedTime(long seconds) { 
    std::string result_string; 
    long mm = seconds / 60; 
    long hh = mm / 60; 
    
    result_string = std::to_string(int(hh)) + ":" + std::to_string(int(mm % 60)) + ":" + std::to_string(int(seconds % 60));  
    return result_string; 
}