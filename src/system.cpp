#include "system.h"

#include <unistd.h>

#include <cstddef>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "linux_parser.h"
#include "process.h"
#include "processor.h"

using std::set;
using std::size_t;
using std::string;
using std::vector;

// Constructor for reading the fixed system information
System::System() {
  this->os_ = LinuxParser::OperatingSystem();
  this->kernel_ = LinuxParser::Kernel();
}

Processor& System::Cpu() { return cpu_; }

vector<Process>& System::Processes() {
  std::vector<int> pid_list = LinuxParser::Pids();
  this->processes_.clear();

  for (unsigned int i = 0; i < pid_list.size(); i++) {
    Process tmp_process(pid_list[i]);
    this->processes_.push_back(tmp_process);
  }

  std::sort(this->processes_.begin(), this->processes_.end());

  return this->processes_;
}

std::string System::Kernel() { return this->kernel_; }

float System::MemoryUtilization() { return LinuxParser::MemoryUtilization(); }

std::string System::OperatingSystem() { return this->os_; }

int System::RunningProcesses() { return LinuxParser::RunningProcesses(); }

int System::TotalProcesses() { return LinuxParser::TotalProcesses(); }

long int System::UpTime() {
  long uptime_in_sec = LinuxParser::UpTime();
  return uptime_in_sec;
}