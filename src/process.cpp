#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"

#include "linux_parser.h"
#include <unistd.h> // to calculate the CPU usage of the process from jiffies to seconds

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
    float procentage_jiffies = static_cast<float>(LinuxParser::ActiveJiffies(this->pid_) + LinuxParser::IdleJiffies(this->pid_)) / static_cast<float>(LinuxParser::Jiffies());
    return procentage_jiffies / sysconf(_SC_CLK_TCK); 
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
    return LinuxParser::UpTime(this->pid_); 
}

// TODO: Overload the "less than" comparison operator for Process objects
// REMOVE: [[maybe_unused]] once you define the function
bool Process::operator<(Process const& a) const { 
    // TODO: Check this function for correct calculation
    float this_jiffies = static_cast<float>(LinuxParser::ActiveJiffies(this->pid_) + LinuxParser::IdleJiffies(this->pid_)) / static_cast<float>(LinuxParser::Jiffies());
    float ref_jiffies = static_cast<float>(LinuxParser::ActiveJiffies(a.pid_) + LinuxParser::IdleJiffies(a.pid_)) / static_cast<float>(LinuxParser::Jiffies()); 
    return (this_jiffies > ref_jiffies) ? true : false; 
}