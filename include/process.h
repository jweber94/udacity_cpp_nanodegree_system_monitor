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
  Process(const int & pid); // TODO: Create the constructor
  int Pid();                               // TODO: See src/process.cpp
  std::string User();                      // TODO: See src/process.cpp
  std::string Command();                   // TODO: See src/process.cpp
  float CpuUtilization();                  // TODO: See src/process.cpp
  std::string Ram();                       // TODO: See src/process.cpp
  long int UpTime();                       // TODO: See src/process.cpp
  bool operator<(Process & a) ;  // TODO: See src/process.cpp

  // TODO: Declare any necessary private members
 private:
    int pid_ = 0; // default is not a valid id 
    std::string command_ = "none"; 
};

#endif