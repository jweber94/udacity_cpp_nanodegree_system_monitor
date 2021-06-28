#include "processor.h"
#include "linux_parser.h"
#include <vector>
#include <string>
#include <unistd.h>

#include <iostream>

// TODO: Return the aggregate CPU utilization
float Processor::Utilization() {  
    // Reference: https://stackoverflow.com/questions/23367857/accurate-calculation-of-cpu-usage-given-in-percentage-in-linux
    std::vector<std::string> current_utilizations = LinuxParser::CpuUtilization();
    
    std::string user_cpu = current_utilizations[0];
    std::string nice_cpu = current_utilizations[1];
    std::string system_cpu = current_utilizations[2];
    std::string idle_cpu = current_utilizations[3];
    std::string iowait_cpu = current_utilizations[4];
    std::string irq_cpu = current_utilizations[5];
    std::string softirq_cpu = current_utilizations[6];
    std::string steal_cpu = current_utilizations[7];
    std::string guest_cpu = current_utilizations[8];

    
    long idle = std::stol(idle_cpu) + std::stol(iowait_cpu); 
    long non_idle = std::stol(user_cpu) + std::stol(nice_cpu) + std::stol(system_cpu) + std::stol(irq_cpu) + std::stol(softirq_cpu) + std::stol(steal_cpu); 
    long total = idle + non_idle; 

    long delta_tot = total - this->prev_total_; 
    long delta_idle = idle - this->prev_idle_; 

    float cpu_precentage = float((delta_tot - delta_idle)) / float(delta_tot); 

    // change the current values to the previous idle in for the next call of the method
    this->prev_idle_ = idle; 
    this->prev_non_idle_ = non_idle; 
    this->prev_total_ = total; 

    //std::cout << "CPU percentage: " << cpu_precentage << std::endl;  
    return cpu_precentage;
}