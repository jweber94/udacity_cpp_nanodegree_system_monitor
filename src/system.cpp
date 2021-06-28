#include <unistd.h>
#include <cstddef>
#include <set>
#include <string>
#include <vector>

#include "process.h"
#include "processor.h"
#include "system.h"

#include "linux_parser.h"

using std::set;
using std::size_t;
using std::string;
using std::vector;

// Constructor for reading the fixed system information
System::System(){
    this->os_ = LinuxParser::OperatingSystem(); 
    this->kernel_ = LinuxParser::Kernel();
}

// TODO: Return the system's CPU
Processor& System::Cpu() { return cpu_; }

// TODO: Return a container composed of the system's processes
vector<Process>& System::Processes() { 
    // Whenever the Processes() Method is called, read the file system and store the information for ALL process PIDs that could be found as a folder in /proc/*    
    std::vector<int> pid_list = LinuxParser::Pids();
    std::vector<Process> process_list; 

    for (int i = 0; i < pid_list.size(); i++){
        Process tmp_process(pid_list[i]); 
        process_list.push_back(tmp_process); 
    } 
    return processes_; 
}

// TODO: Return the system's kernel identifier (string)
std::string System::Kernel() { 
    return this->kernel_; 
}

// TODO: Return the system's memory utilization
float System::MemoryUtilization() { 
    return LinuxParser::MemoryUtilization(); 
}

// TODO: Return the operating system name
std::string System::OperatingSystem() { 
    return this->os_;   
}

// TODO: Return the number of processes actively running on the system
int System::RunningProcesses() { 
    return LinuxParser::RunningProcesses(); 
}

// TODO: Return the total number of processes on the system
int System::TotalProcesses() { 
    return LinuxParser::TotalProcesses(); 
}

// TODO: Return the number of seconds since the system started running
long int System::UpTime() {  
    return LinuxParser::UpTime(); 
}