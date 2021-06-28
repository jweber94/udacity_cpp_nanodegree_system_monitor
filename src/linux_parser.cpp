#include "linux_parser.h"

#include <dirent.h>
#include <unistd.h>

#include <cassert>
#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using std::stof;
using std::string;
using std::to_string;
using std::vector;

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

float LinuxParser::MemoryUtilization() {
  // cache all memory related information to make it possible to create more
  // sophisticated functionallities in the future
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

  return (mem_tot - mem_ffree) / mem_tot;
}

long LinuxParser::UpTime() {
  /*
   * Returns the uptime of the system in seconds
   *
   * Explaination of uptime:
   * https://unix.stackexchange.com/questions/275907/on-linux-when-does-uptime-start-counting-from
   * https://man7.org/linux/man-pages/man5/proc.5.html - search for
   * "/proc/uptime" and you can see, that we are looking for the first element
   * in the file.
   */
  std::string line, uptime, idle_time;
  std::ifstream uptime_stream(kProcDirectory + kUptimeFilename);
  if (uptime_stream.is_open()) {
    std::getline(uptime_stream, line);
    std::istringstream linestream_instance(line);
    linestream_instance >> uptime >> idle_time;
    return static_cast<long>(std::stof(uptime));
  } else {
    std::cerr << "Could not open /proc/uptime\n";
    exit(0);
  }
}

long LinuxParser::Jiffies() {
  return LinuxParser::ActiveJiffies() + LinuxParser::IdleJiffies();
}

long LinuxParser::ActiveJiffies(int pid) {
  // Returns the number of jiffies (= clock ticks) that the process with the
  // corresponding PID has spend actively on the cpu
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
    result_jiffies = std::stol(utime) + std::stol(sstime) + std::stol(cutime) +
                     std::stol(cstime);
    return result_jiffies;
  } else {
    std::cerr << "Could not read jiffies for the PID " << pid << "\n";
    exit(0);
  }
}

long LinuxParser::ActiveJiffies() {
  // Returns the number of jiffies (= clock ticks) that the cpu spends in active
  // modes (user mode, nice mode, system mode). The information could be found
  // in /proc/stat after the cpu key. You can look up the itemization in
  // https://man7.org/linux/man-pages/man5/procfs.5.html if you are searching
  // for "/proc/stat"
  std::string line, key, user_jif, nice_jif, system_jif, idle_jif;
  std::ifstream active_jif_stream(kProcDirectory + kStatFilename);

  if (active_jif_stream.is_open()) {
    std::getline(active_jif_stream, line);
    std::stringstream cpu_sstream(
        line);  // the cummulated system cpu information is stored only in the
                // first line
    cpu_sstream >> key >> user_jif >> nice_jif >> system_jif >> idle_jif;
    return std::stol(user_jif) + std::stol(nice_jif) + std::stol(system_jif);
  } else {
    std::cerr << "Could not open /proc/stat\n";
    exit(0);
  }
}

long LinuxParser::IdleJiffies(int pid) {
  // Returns the number of jiffies (= clock ticks) that the process with the
  // corresponding PID has spend passivly on the cpu (= idle)

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
        pid_jiff_stream >> sstime;
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
    result_jiffies = std::stol(cutime) + std::stol(cstime);
    return result_jiffies;
  } else {
    std::cerr << "Could not read jiffies for the PID " << pid << "\n";
    exit(0);
  }
}

long LinuxParser::IdleJiffies() {
  // Returns the number of jiffies (= clock ticks) that the cpu spends in active
  // modes (user mode, nice mode, system mode). The information could be found
  // in /proc/stat after the cpu key. You can look up the itemization in
  // https://man7.org/linux/man-pages/man5/procfs.5.html if you are searching
  // for "/proc/stat"
  std::string line, key, user_jif, nice_jif, system_jif, idle_jif;
  std::ifstream active_jif_stream(kProcDirectory + kStatFilename);

  if (active_jif_stream.is_open()) {
    std::getline(active_jif_stream, line);
    std::stringstream cpu_sstream(
        line);  // the cummulated system cpu information is stored only in the
                // first line
    cpu_sstream >> key >> user_jif >> nice_jif >> system_jif >> idle_jif;
    return std::stol(
        idle_jif);  // iowait is not included, since it is not a relieable value
                    // (i.e. https://man7.org/linux/man-pages/man5/procfs.5.html
                    // search for /proc/stat)
  } else {
    std::cerr << "Could not open /proc/stat\n";
    exit(0);
  }
}

vector<string> LinuxParser::CpuUtilization() {
  /*
   * Resulting datastructure:
   * 0: user_cpu;
   * 1: nice_cpu;
   * 2: system_cpu;
   * 3: idle_cpu;
   * 4: iowait_cpu;
   * 5: irq_cpu;
   * 6: softirq_cpu;
   * 7: steal_cpu;
   * 8: guest_cpu;
   */

  std::vector<std::string> cpu_vector;
  // Explaination, how to read the system cpu information from the /proc/stat
  // file: https://www.idnt.net/en-US/kb/941772
  std::string line, name, user_cpu, nice_cpu, system_cpu, idle_cpu, iowait_cpu,
      irq_cpu, softirq_cpu, steal_cpu, guest_cpu;
  std::ifstream cpu_usage_stream(kProcDirectory + kStatFilename);

  if (cpu_usage_stream.is_open()) {
    // no while loop, since the first line contains the cpu information
    // aggregated
    std::getline(cpu_usage_stream, line);
    std::stringstream line_stream(line);

    line_stream >> name >> user_cpu >> nice_cpu >> system_cpu >> idle_cpu >>
        iowait_cpu >> irq_cpu >> softirq_cpu >> steal_cpu >> guest_cpu;

    cpu_vector.push_back(user_cpu);
    cpu_vector.push_back(nice_cpu);
    cpu_vector.push_back(system_cpu);
    cpu_vector.push_back(idle_cpu);
    cpu_vector.push_back(iowait_cpu);
    cpu_vector.push_back(irq_cpu);
    cpu_vector.push_back(softirq_cpu);
    cpu_vector.push_back(steal_cpu);
    cpu_vector.push_back(guest_cpu);

    assert(cpu_vector.size() == 9);

    return cpu_vector;

  } else {
    std::cerr << "Could not open /proc/stat\n";
    exit(0);
  }
}

int LinuxParser::TotalProcesses() {
  // Returns the total number of processes (forks from the main processes with
  // PID 1) since boot
  std::string line, tmp_str, num_proc;
  std::ifstream cpu_usage_stream(kProcDirectory + kStatFilename);
  int num_processes;

  if (cpu_usage_stream.is_open()) {
    while (std::getline(cpu_usage_stream, line)) {
      // look throu all first elements and check if the line with processes is
      // reached, if so save the number of processes
      std::stringstream line_stream(line);
      line_stream >> tmp_str;
      if (tmp_str == "processes") {
        line_stream >> num_proc;
        break;  // if we found the processes line, stop the loop for searching
                // the processes line since we already found it
      }
    }
    num_processes = std::stoi(num_proc);
    return num_processes;

  } else {
    std::cerr << "Could not open /proc/stat\n";
    exit(0);
  }
}

int LinuxParser::RunningProcesses() {
  std::string line, tmp_str, num_proc;
  std::ifstream cpu_usage_stream(kProcDirectory + kStatFilename);
  int num_processes;

  if (cpu_usage_stream.is_open()) {
    while (std::getline(cpu_usage_stream, line)) {
      // look throu all first elements and check if the line with processes is
      // reached, if so save the number of processes
      std::stringstream line_stream(line);
      line_stream >> tmp_str;
      if (tmp_str == "procs_running") {
        line_stream >> num_proc;
        break;  // if we found the processes line, stop the loop for searching
                // the processes line since we already found it
      }
    }
    num_processes = std::stoi(num_proc);
    return num_processes;

  } else {
    std::cerr << "Could not open /proc/stat\n";
    exit(0);
  }
  return 0;
}

string LinuxParser::Command(int pid) {
  std::string exec_command, tmp_str;
  std::ifstream command_stream(kProcDirectory + std::to_string(pid) +
                               kCmdlineFilename);

  if (command_stream.is_open()) {
    // The cmdline file has just one line, so we can read the complete line at
    // once if we do not want to extract special information from it
    std::getline(command_stream, exec_command);
    return exec_command;

  } else {
    std::cerr << "Could not open /proc/" << pid << "/cmdline\n";
    exit(0);
  }
}

string LinuxParser::Ram(int pid) {
  std::string ram_usage, tmp_key, line;
  std::ifstream ram_stream(kProcDirectory + "/" + std::to_string(pid) +
                           kStatusFilename);
  if (ram_stream.is_open()) {
    while (std::getline(ram_stream, line)) {
      std::stringstream line_stream(line);
      line_stream >> tmp_key;
      if (tmp_key == "VmRSS:") {
        // Reference:
        // https://serverfault.com/questions/138427/what-does-virtual-memory-size-in-top-mean
        // and https://man7.org/linux/man-pages/man5/proc.5.html
        line_stream >> ram_usage;

        // calculate RAM in MB since we just can parse it in KB
        float tmp_ram = (std::stof(ram_usage) / 1000.f);
        float ram = floorf(tmp_ram * 100) / 100;
        int precisionVal = 2;  // number of decimal points for the print out

        std::string printout_ram = std::to_string(ram).substr(
            0, std::to_string(ram).find(".") + precisionVal + 1);
        return printout_ram;
      }
    }
  } else {
    std::cerr << "Could not open /proc/" << pid << "/status\n";
    exit(0);
  }
}

string LinuxParser::Uid(int pid) {
  std::string line, tmp_key, uid;
  std::ifstream uid_stream(kProcDirectory + "/" + std::to_string(pid) +
                           kStatusFilename);

  if (uid_stream.is_open()) {
    while (std::getline(uid_stream, line)) {
      std::stringstream linestream(line);
      linestream >> tmp_key;
      if (tmp_key == "Uid:") {
        linestream >> uid;
        return uid;
      }
    }
  } else {
    std::cerr << "Could not read /proc/" << pid << "/status\n";
    exit(0);
  }
}

string LinuxParser::User(int pid) {
  std::string line, uid_process;
  std::ifstream user_stream(kPasswordPath);
  std::string pass, uid;
  std::string username{"NoUser"};

  uid_process = LinuxParser::Uid(pid);

  if (user_stream.is_open()) {
    while (std::getline(user_stream, line)) {
      // read out the passwd file and go throu all lines until the uid was
      // found. Then get the username based on the uid from the first element of
      // the line - Explaination of the passwd file:
      // https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
      std::replace(
          line.begin(), line.end(), ':',
          ' ');  // The data in /etc/passwd is colon sepatated - to read it out
                 // with a stringstream we need to separate it by spaces
      std::stringstream linestream(line);
      linestream >> username >> pass >> uid;
      if (uid == uid_process) {
        return username;
      }
    }
  } else {
    std::cerr << "Could not open " << kPasswordPath << "\n";
    exit(0);
  }
}

long LinuxParser::UpTime(int pid) {
  std::string line, tmp_element, uptime;
  std::ifstream uptime_pid_stream(kProcDirectory + "/" + std::to_string(pid) +
                                  kStatFilename);
  // Returns the uptime of a process in jiffies

  if (uptime_pid_stream.is_open()) {
    std::getline(uptime_pid_stream,
                 line);  // the stat file has always just one line
    std::stringstream linestream(line);

    // iterate until the uptime element of the process is the next one to parse
    // from the stringstream
    for (int i = 1; i < 22; i++) {
      linestream >> tmp_element;
    }
    // parse the uptime
    linestream >> uptime;  // uptime in jiffies

    // std::cout << "The uptime of " << pid << " is: " << std::stol(uptime) <<
    // "\n";

    return std::stol(uptime);
  } else {
    std::cerr << "Could not open /proc/" << pid << "/stat\n";
    exit(0);
  }
}

long LinuxParser::StartTime(int pid) {
  // Returns the start time of the process in jiffies
  std::ifstream pid_jiffies_stream(kProcDirectory + "/" + std::to_string(pid) +
                                   kStatFilename);
  std::string starttime, line, tmp;

  if (pid_jiffies_stream.is_open()) {
    std::getline(pid_jiffies_stream, line);
    std::stringstream pid_jiff_stream(line);

    // walk throu the cpu data in the first line of the file until the start
    // time of the process appears at the index 21
    for (int i = 0; i < 20; i++) {
      pid_jiff_stream >> tmp;
    }
    // extract the start time
    pid_jiff_stream >> starttime;

    return std::stol(starttime);
  } else {
    std::cerr << "Could not read jiffies for the PID " << pid << "\n";
    exit(0);
  }
}
