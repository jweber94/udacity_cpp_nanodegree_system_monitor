#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"

#include "linux_parser.h"
#include <unistd.h> // to calculate the CPU usage of the process from jiffies to seconds
#include <iostream> //debug

using std::string;
using std::to_string;
using std::vector;

// Constructor
Process::Process(const int & pid){
    this->pid_ = pid; 
    this->command_ = LinuxParser::Command(pid); 
}

// TODO: Return this process's ID
int Process::Pid() { 
    return this->pid_; 
}

// TODO: Return this process's CPU utilization
float Process::CpuUtilization() { 
    // Calculation based on: https://stackoverflow.com/questions/16726779/how-do-i-get-the-total-cpu-usage-of-an-application-from-proc-pid-stat
    long total_time = LinuxParser::ActiveJiffies(this->pid_); 
    long start_time = LinuxParser::StartTime(this->pid_); 
    
    long seconds = LinuxParser::UpTime() - long(float(start_time) / sysconf(_SC_CLK_TCK));  

    float cpu_usage = ((total_time / sysconf(_SC_CLK_TCK)) / float(seconds));
    return cpu_usage; 
}

// TODO: Return the command that generated this process
string Process::Command() { 
    return this->command_; 
}

// TODO: Return this process's memory utilization
string Process::Ram() { 
    return LinuxParser::Ram(this->pid_); 
}

// TODO: Return the user (name) that generated this process
string Process::User() { 
    return LinuxParser::User(this->pid_); 
}

// TODO: Return the age of this process (in seconds)
long int Process::UpTime() { 
    //std::cout << "Process uptime: " << LinuxParser::UpTime(this->pid_) << "\n"; 
    return LinuxParser::UpTime(this->pid_); 
}

// TODO: Overload the "less than" comparison operator for Process objects
// REMOVE: [[maybe_unused]] once you define the function
bool Process::operator<(Process & a) { 
    float cpu_usage_this = this->CpuUtilization(); 
    float cpu_usage_ref = a.CpuUtilization(); 
    return (cpu_usage_this > cpu_usage_ref) ? true : false; 
}