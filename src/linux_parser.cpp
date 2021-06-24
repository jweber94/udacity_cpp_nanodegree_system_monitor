#include "linux_parser.h"

#include <dirent.h>
#include <unistd.h>

#include <iostream>  // for Debugging
#include <sstream>
#include <string>
#include <vector>

using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, kernel, version;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() {
  // cache all memory related information to make it possible to create more
  // sophisticated functionallities in the future
  float result_mem_utilization = 0.f;
  float mem_tot, mem_ffree, mem_availf, mem_buffer;
  std::string line, mem_total, mem_free, mem_avail, buffers, tmp_key, tmp_value;
  std::ifstream mem_util_stream(kProcDirectory + kMeminfoFilename);
  bool mem_tot_b, mem_free_b, mem_avail_b, buffers_b = false;

  // parse the memory information
  if (mem_util_stream.is_open()) {
    while (std::getline(mem_util_stream,
                        line)) {  // delivers true, as long as we can read new
                                  // lines from the string
      std::istringstream linestream(line);
      linestream >> tmp_key >> tmp_value;
      if (tmp_key == "MemTotal:") {
        mem_total = tmp_value;
        mem_tot_b = true;
      } else if (tmp_key == "MemFree:") {
        mem_free = tmp_value;
        mem_free_b = true;
      } else if (tmp_key == "MemAvailable:") {
        mem_avail = tmp_value;
        mem_avail_b = true;
      } else if (tmp_key == "Buffers:") {
        buffers = tmp_value;
        buffers_b = true;
      } else {
        if (mem_tot_b && mem_free_b && mem_avail_b && buffers_b) {
          break;
        } else {
          continue;
        }
      }
    }
  } else {
    std::cerr << "Could not open /proc/meminfo\n";
    exit(0);
  }

  // calculate memory utilization
  mem_tot = std::stof(mem_total);
  mem_ffree = std::stof(mem_free);
  mem_availf = std::stof(mem_avail);
  mem_buffer = std::stof(buffers);

  result_mem_utilization = (mem_tot - mem_ffree) / mem_tot;
  return result_mem_utilization;
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() {
  // Explaination of uptime:
  // https://unix.stackexchange.com/questions/275907/on-linux-when-does-uptime-start-counting-from
  std::string line, uptime, idle_time;
  std::ifstream uptime_stream(kProcDirectory + kUptimeFilename);
  if (uptime_stream.is_open()) {
    std::getline(uptime_stream, line);
    std::istringstream linestream_instance(line);
    linestream_instance >> uptime >> idle_time;
  } else {
    std::cerr << "Could not open /proc/uptime\n";
    exit(0);
  }
  long uptime_result = std::stol(uptime);

  // DEBUG
  std::cout << "uptime as long is: " << uptime_result << "\n";

  return uptime_result;
}

// TODO: Read and return the number of jiffies for the system
// FIXME: Check this again
long LinuxParser::Jiffies() {
  return LinuxParser::ActiveJiffies() + LinuxParser::IdleJiffies(); 
}

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid) {
  std::ifstream pid_jiffies_stream(kProcDirectory + "/" + std::to_string(pid) +
                                   kStatFilename);
  std::string utime, sstime, cutime, cstime, starttime, line, tmp;

  if (pid_jiffies_stream.is_open()) {
    // use just one line since the stat file for a PID contains always just one
    // line
    std::getline(pid_jiffies_stream, line);
    std::stringstream pid_jiff_stream(line);
    long result_jiffies = 0;

    // go throu the string until the 14 to 17, as well as the 22 element is
    // reached and saved. Extract all jiffies for the process in order to be
    // prepared to extend the project
    for (int i = 0; i < 22; i++) {
      if (i == 13) {
        pid_jiff_stream >> utime;
      } else if (i == 14) {
        pid_jiff_stream >> sstime;  // sstime, since stime is a C++ keyword
      } else if (i == 15) {
        pid_jiff_stream >> cutime;
      } else if (i == 16) {
        pid_jiff_stream >> cstime;
      } else if (i == 21) {
        pid_jiff_stream >> starttime;
      } else {
        pid_jiff_stream >> tmp;
      }
    }
    result_jiffies =
        std::stol(utime) +
        std::stol(
            sstime);  // calculation based on:
                      // https://stackoverflow.com/questions/16726779/how-do-i-get-the-total-cpu-usage-of-an-application-from-proc-pid-stat/16736599#16736599
    return result_jiffies;
  } else {
    std::cerr << "Could not read jiffies for the PID " << pid << "\n";
    exit(0);
  }
}

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() {
  std::vector<int> current_pids = LinuxParser::Pids();
  long result = 0;

  // sum op all jiffies of the current PIDs
  for (const auto& tmp_pid : current_pids) {
    result += LinuxParser::ActiveJiffies(tmp_pid);
  }

  return result;
}

long LinuxParser::IdleJiffies(int pid) {
  // As idle jiffies we define everything, that is related to a process but not
  // the process itself
  std::ifstream pid_jiffies_stream(kProcDirectory + "/" + std::to_string(pid) +
                                   kStatFilename);
  std::string utime, sstime, cutime, cstime, starttime, line, tmp;

  if (pid_jiffies_stream.is_open()) {
    // use just one line since the stat file for a PID contains always just one
    // line
    std::getline(pid_jiffies_stream, line);
    std::stringstream pid_jiff_stream(line);
    long result_jiffies = 0;

    // go throu the string until the 14 to 17, as well as the 22 element is
    // reached and saved. Extract all jiffies for the process in order to be
    // prepared to extend the project
    for (int i = 0; i < 22; i++) {
      if (i == 13) {
        pid_jiff_stream >> utime;
      } else if (i == 14) {
        pid_jiff_stream >> sstime;  // sstime, since stime is a C++ keyword
      } else if (i == 15) {
        pid_jiff_stream >> cutime;
      } else if (i == 16) {
        pid_jiff_stream >> cstime;
      } else if (i == 21) {
        pid_jiff_stream >> starttime;
      } else {
        pid_jiff_stream >> tmp;
      }
    }
    result_jiffies =
        std::stol(cutime) +
        std::stol(
            cstime);  // calculation based on:
                      // https://stackoverflow.com/questions/16726779/how-do-i-get-the-total-cpu-usage-of-an-application-from-proc-pid-stat/16736599#16736599
    return result_jiffies;
  } else {
    std::cerr << "Could not read jiffies for the PID " << pid << "\n";
    exit(0);
  }
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() {
  std::vector<int> current_pids = LinuxParser::Pids();
  long result = 0;

  // sum op all jiffies of the current PIDs
  for (const auto& tmp_pid : current_pids) {
    result += LinuxParser::IdleJiffies(tmp_pid);
  }
  return result;
}

// TODO: Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() { 
  
  // Intro to jiffies:
  // https://cyberglory.wordpress.com/2011/08/21/jiffies-in-linux-kernel/ We
  // want the system wide jiffies, which you can read out from the first number
  // cpu: Key in /proc/stat
  long result_jiffies = 0;
  std::string system_jiffies, line, tmp_key, tmp_val;
  std::ifstream jiffie_stream(kProcDirectory + kStatFilename);
  bool jiffies_found_b = false;

  if (jiffie_stream.is_open()) {
    while (std::getline(jiffie_stream, line)) {
      // read throu the line
      while (jiffie_stream >> tmp_key >> tmp_val) {
        if (tmp_key == "cpu") {
          result_jiffies = std::stol(tmp_val);
          return result_jiffies;
        }
      }
    }
  }

  return {};   
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() { return 0; }

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() { return 0; }

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid [[maybe_unused]]) { return string(); }

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid [[maybe_unused]]) { return string(); }

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid [[maybe_unused]]) { return string(); }

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid [[maybe_unused]]) { return string(); }

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid [[maybe_unused]]) { return 0; }
