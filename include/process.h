#ifndef PROCESS_H
#define PROCESS_H

#include <string>
/*
Basic class for Process representation
It contains relevant attributes as shown below
*/
class Process {
 public:
  Process() = delete;
  Process(const int& pid);
  int Pid();
  std::string User();
  std::string Command();
  float CpuUtilization();
  std::string Ram();
  long int UpTime();
  bool operator<(Process& a);

 private:
  int pid_ = 0;
  std::string command_ = "none";
};

#endif