#include "processor.h"
#include "linux_parser.h"
#include <vector>
#include <string>
#include <unistd.h>

// TODO: Return the aggregate CPU utilization
float Processor::Utilization() { 
    std::vector<std::string> cpu_utils = LinuxParser::CpuUtilization(); 
    float cpu_utilization = 0; // the result must be in the range 0 to 1 
    for (auto cpu_element : cpu_utils){
        cpu_utilization += std::stof(cpu_element); 
    }
    return (cpu_utilization / static_cast<float>(LinuxParser::UpTime())) / sysconf(_SC_CLK_TCK); 
}