#include "process.h"

#include <unistd.h>
#include <unistd.h>  // sysconf(_SC_CLK_TCK)

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;

// Constructor
Process::Process(const int& pid) {
  this->pid_ = pid;
  this->command_ = LinuxParser::Command(pid);
}

int Process::Pid() { return this->pid_; }

float Process::CpuUtilization() {
  // Calculation based on:
  // https://stackoverflow.com/questions/16726779/how-do-i-get-the-total-cpu-usage-of-an-application-from-proc-pid-stat
  long total_time = LinuxParser::ActiveJiffies(this->pid_);
  long start_time = LinuxParser::StartTime(this->pid_);

  long seconds =
      LinuxParser::UpTime() - long(float(start_time) / sysconf(_SC_CLK_TCK));

  float cpu_usage = ((total_time / sysconf(_SC_CLK_TCK)) / float(seconds));
  return cpu_usage;
}

string Process::Command() { return this->command_; }

string Process::Ram() { return LinuxParser::Ram(this->pid_); }

string Process::User() { return LinuxParser::User(this->pid_); }

long int Process::UpTime() { return LinuxParser::UpTime(this->pid_); }

bool Process::operator<(Process& a) {
  float cpu_usage_this = this->CpuUtilization();
  float cpu_usage_ref = a.CpuUtilization();
  return (cpu_usage_this > cpu_usage_ref) ? true : false;
}