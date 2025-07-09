// input_generator_debug.cpp
// Version with debug output and security features
// Usage: ./input_generator_debug <source_code_string> [time_limit(seconds)] [memory_limit(MB)] [input_list] [security_options]
//
// Security features:
// 1. System call whitelist - Only allows Python programs to use safe system calls
// 2. Resource limits - Limits CPU time, memory usage, file size, etc.
// 3. Privilege dropping - Runs evaluated programs as non-privileged users
// 4. Network isolation - Prevents programs from accessing network resources
// 5. ptrace monitoring - Real-time monitoring of program system call behavior
//
// Security options:
// --debug: Enable detailed debug output
// --ptrace: Enable ptrace system call monitoring (provides stronger security but may impact performance)
//
// Note: Needs to run with root privileges to set security limits, the program automatically drops to non-privileged user to execute code

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <math.h>
#include <atomic>
#include <sys/mount.h>

// Compatibility definitions
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

#ifndef MS_BIND
#define MS_BIND 4096
#endif

#ifndef MS_REMOUNT
#define MS_REMOUNT 32
#endif

#ifndef MS_RDONLY
#define MS_RDONLY 1
#endif

#ifndef __WALL
#define __WALL 0x40000000
#endif

// Remove custom ptrace macro definitions, use system-provided constants
// Define missing ptrace constants on macOS
#ifdef __APPLE__
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif

#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif

#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 0x00000002
#endif

#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK 0x00000004
#endif

#ifndef PTRACE_SYSCALL
#define PTRACE_SYSCALL 24
#endif

#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS 12
#endif

#ifndef PTRACE_KILL
#define PTRACE_KILL 8
#endif

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif
#endif

// System call number compatibility definitions
#ifndef SYS_brk
#define SYS_brk 12
#endif

#ifndef SYS_rt_sigaction
#define SYS_rt_sigaction 13
#endif

#ifndef SYS_rt_sigprocmask
#define SYS_rt_sigprocmask 14
#endif

#ifndef SYS_newfstatat
#define SYS_newfstatat 262
#endif

// unshare function declaration (if system doesn't support)
#ifndef __APPLE__
extern "C" int unshare(int flags);
extern "C" int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#else
// macOS doesn't support unshare, define as failure
static inline int unshare(int flags) {
    errno = ENOSYS;
    return -1;
}
// macOS doesn't support setresuid, define as failure
static inline int setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    errno = ENOSYS;
    return -1;
}
#endif

// Register structure compatibility
#ifdef __APPLE__
// macOS doesn't support full ptrace functionality, define empty structure
struct user_regs_struct {
    unsigned long long orig_rax;
    unsigned long long rax;
};
#endif

#define OJ_WT0 0     // Waiting
#define OJ_AC 4      // Answer Correct
#define OJ_PE 5      // Presentation Error
#define OJ_WA 6      // Wrong Answer
#define OJ_TL 7      // Time Limit Exceeded
#define OJ_ML 8      // Memory Limit Exceeded
#define OJ_OL 9      // Output Limit Exceeded
#define OJ_RE 10     // Runtime Error
#define OJ_CE 11     // Compilation Error

#define STD_MB 1048576LL
#define BUFFER_SIZE 4096
#define MAX_OUTPUT_SIZE 1024 * 1024 * 1024  // 1GB output limit

// Security-related constants
#define JUDGE_UID 1536
#define JUDGE_GID 1536

// Language constants (from judge_client.cc)
#define LANG_C 0
#define LANG_CPP 1  
#define LANG_PYTHON 6

// System call whitelist size
#define CALL_ARRAY_SIZE 512

// C++ system call whitelist (based on LANG_CV in judge_client.cc)
static int cpp_allowed_syscalls[] = {
    // Basic system calls
    0,1,2,3,4,5,6,8,9,10,11,12,13,14,16,17,21,32,39,41,42,49,59,72,78,79,89,97,99,102,104,106,107,108,131,137,158,186,202,217,218,228,231,257,262,273,302,318,334,
    
    // LANG_CV specific system calls from okcalls64.h
    1,    // SYS_write
    10,   // SYS_mprotect  
    102,  // SYS_getuid
    11,   // SYS_munmap
    12,   // SYS_brk
    13,   // SYS_rt_sigaction
    14,   // SYS_rt_sigprocmask
    158,  // SYS_arch_prctl
    16,   // SYS_ioctl
    17,   // SYS_pread64
    2,    // SYS_open
    202,  // SYS_futex
    21,   // SYS_access
    217,  // SYS_getdents64
    218,  // SYS_set_tid_address
    231,  // SYS_exit_group
    257,  // SYS_openat
    273,  // SYS_set_robust_list
    3,    // SYS_close
    302,  // SYS_prlimit64
    39,   // SYS_getpid
    4,    // SYS_stat
    5,    // SYS_fstat
    59,   // SYS_execve
    6,    // SYS_lstat
    60,   // SYS_exit
    72,   // SYS_fcntl
    78,   // SYS_getdents
    79,   // SYS_getcwd
    8,    // SYS_lseek
    89,   // SYS_readlink
    9,    // SYS_mmap
    97,   // SYS_getrlimit
    99,   // SYS_sysinfo
    
    // End marker (using -1 instead of 0, because 0 is a valid system call number)
    -1
};

// Python system call whitelist (completely based on LANG_YV in okcalls64.h)
// Includes numeric system call numbers + all system calls defined in SYS_
static int python_allowed_syscalls[] = {
    // Numeric system call numbers (exactly the same as LANG_YV)
    0,1,2,3,4,5,6,8,9,10,11,12,13,14,16,17,21,32,39,41,42,49,59,72,78,79,89,97,99,102,104,106,107,108,131,137,158,186,202,217,218,228,231,257,262,273,302,318,334,
    511,
    
    // SYS_ definitions (exactly the same as LANG_YV)
    // Basic system calls
    1,    // SYS_write
    10,   // SYS_mprotect  
    102,  // SYS_getuid
    104,  // SYS_getgid
    107,  // SYS_geteuid
    108,  // SYS_getegid
    11,   // SYS_munmap
    12,   // SYS_brk
    
    // Signal handling
    13,   // SYS_rt_sigaction
    131,  // SYS_sigaltstack
    14,   // SYS_rt_sigprocmask
    141,  // SYS_sched_get_priority_max
    158,  // SYS_arch_prctl
    16,   // SYS_ioctl
    
    // File operations
    17,   // SYS_pread64
    191,  // SYS_getxattr
    2,    // SYS_open
    202,  // SYS_futex
    21,   // SYS_access
    217,  // SYS_getdents64
    218,  // SYS_set_tid_address
    228,  // SYS_clock_gettime
    231,  // SYS_exit_group
    25,   // SYS_mremap
    257,  // SYS_openat
    272,  // SYS_unshare
    273,  // SYS_set_robust_list
    3,    // SYS_close
    302,  // SYS_prlimit64
    
    // Process operations
    32,   // SYS_dup
    39,   // SYS_getpid
    4,    // SYS_stat
    41,   // SYS_socket
    42,   // SYS_connect
    5,    // SYS_fstat
    59,   // SYS_execve
    6,    // SYS_lstat
    
    // System information
    60,   // SYS_exit
    72,   // SYS_fcntl
    78,   // SYS_getdents
    79,   // SYS_getcwd
    8,    // SYS_lseek
    89,   // SYS_readlink
    9,    // SYS_mmap
    97,   // SYS_getrlimit
    99,   // SYS_sysinfo
    
    // Add missing system calls based on actual runtime needs and error logs
    58,   // vfork - Python child process creation needed
    87,   // unlink - file deletion operation needed (this is the intercepted system call)
    291,  // epoll_pwait - asynchronous I/O needed  
    293,  // pipe2 - pipe operation needed
    
    // End marker (using -1 instead of 0, because 0 is a valid system call number)
    -1
};

// Calculate length of whitelist arrays
#define PYTHON_SYSCALLS_COUNT (sizeof(python_allowed_syscalls) / sizeof(python_allowed_syscalls[0]))

#define HOJ_MAX_LIMIT 999999

// Global variables
static int detected_language = LANG_PYTHON;  // Detected language
static int use_ptrace = 0;  // Whether to use ptrace monitoring
static int DEBUG = 0;       // Debug mode
static int call_counter[CALL_ARRAY_SIZE] = {0};  // System call counter
static unsigned int call_id = 0;
static char sandbox_dir[256] = {0};  // Save sandbox directory path for cleanup
static std::atomic<bool> g_in_signal_handler(false);  // Prevent re-entry in signal handler

// Debug output function implementation
void debug_print(const char* fmt, ...) {
    if (!DEBUG) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// Function forward declarations
void timeout_handler(int signo);
void escape_json_string(const char* input, char* output, size_t max_size);
void output_json_item(const char* input, const char* output, const char* expected_output, const char* error, const char* traceback, const char* status, bool is_last);
void output_json_array(const std::vector<std::string>& inputs, const std::vector<std::string>& outputs, 
                     const std::vector<std::string>& expected_outputs,
                     const std::vector<std::string>& errors, const std::vector<std::string>& tracebacks, 
                     const std::vector<std::string>& statuses);
int detect_language(const char* source_code);
int compile_cpp_code(const char* source_code, char* executable_path, char* error_output);
int run_and_get_output(const char* source_code, double time_limit, int memory_limit, const char* input, char* output, char* error);
int run_executable(const char* executable_path, double time_limit, int memory_limit, const char* input, char* output, char* error);
int compare_outputs(const std::string& output, const std::string& expected_output);
const char* find_matching_bracket(const char* start);
bool parse_json_input(const char* json_str, std::vector<std::string>& inputs, std::vector<std::string>& expected_outputs);
void setup_process_isolation(const char* local_sandbox_dir);
void cleanup_temp_files(const char* temp_path, const char* stdin_path, const char* stdout_path, const char* stderr_path, bool has_input);
void cleanup_compare_files(const char* user_output_file, const char* expected_output_file);
void cleanup_sandbox_directory();
void umount_work_directory(const char* work_dir);
void enhanced_monitor_process(pid_t pidApp, double time_limit, int &ACflg, long long &topmemory, 
                            long long mem_lmt, int &usedtime, const char* infile);

// Initialize system call whitelist (completely based on judge_client.cc implementation)
void init_syscalls_limits() {
    memset(call_counter, 0, sizeof(call_counter));
    
    int* allowed_syscalls;
    int count;
    const char* lang_name;
    
    if (detected_language == LANG_CPP || detected_language == LANG_C) {
        allowed_syscalls = cpp_allowed_syscalls;
        lang_name = (detected_language == LANG_CPP) ? "C++" : "C";
        // Calculate length of C++ whitelist
        count = 0;
        while (allowed_syscalls[count] != -1) count++;
    } else {
        allowed_syscalls = python_allowed_syscalls;
        lang_name = "Python";
        count = PYTHON_SYSCALLS_COUNT;
    }
    
    debug_print("Initializing %s system call whitelist", lang_name);
    
    // First, display the first few elements of the whitelist array for debugging
    debug_print("First 10 elements of whitelist array: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d", 
                allowed_syscalls[0], allowed_syscalls[1], allowed_syscalls[2], 
                allowed_syscalls[3], allowed_syscalls[4], allowed_syscalls[5],
                allowed_syscalls[6], allowed_syscalls[7], allowed_syscalls[8], 
                allowed_syscalls[9]);
    
    debug_print("Total length of whitelist array: %d", count);
    
    // Set system call whitelist
    int allowed_count = 0;
    for (int i = 0; i < count; i++) {
        int syscall_index = allowed_syscalls[i] % CALL_ARRAY_SIZE;
        call_counter[syscall_index] = HOJ_MAX_LIMIT;
        allowed_count++;
        if (allowed_count <= 10) {  // Only display the first 10 for debugging
            debug_print("Allowed system call: %d (index: %d)", allowed_syscalls[i], syscall_index);
        }
    }
    debug_print("Total %d system calls allowed", allowed_count);
    
    // execve only allowed once (consistent with judge_client.cc)
    call_counter[SYS_execve % CALL_ARRAY_SIZE] = 1;
    debug_print("System call whitelist initialized, execve limited to 1 use");
    debug_print("SYS_execve:%d [%d]", SYS_execve % CALL_ARRAY_SIZE, call_counter[SYS_execve % CALL_ARRAY_SIZE]);
    
    // Debug information: Display status of key system calls
    debug_print("Checking status of key system calls:");
    debug_print("- brk(12): %d", call_counter[12 % CALL_ARRAY_SIZE]);
    debug_print("- execve(%d): %d", SYS_execve, call_counter[SYS_execve % CALL_ARRAY_SIZE]);
    debug_print("- read(0): %d", call_counter[0 % CALL_ARRAY_SIZE]);
    debug_print("- write(1): %d", call_counter[1 % CALL_ARRAY_SIZE]);
}


// Set security-related resource limits
void set_security_limits(double time_limit, int memory_limit) {
    struct rlimit lim;
    
    debug_print("Setting security resource limits");
    
    // Set CPU time limit
    lim.rlim_cur = lim.rlim_max = (int)(time_limit + 1);
    if (setrlimit(RLIMIT_CPU, &lim) == -1) {
        debug_print("Failed to set CPU time limit: %s", strerror(errno));
    } else {
        debug_print("CPU time limit set to: %d seconds", (int)(time_limit + 1));
    }
    
    // Set memory limit
    lim.rlim_cur = lim.rlim_max = memory_limit * STD_MB;
    if (setrlimit(RLIMIT_AS, &lim) == -1) {
        debug_print("Failed to set memory limit: %s", strerror(errno));
    } else {
        debug_print("Memory limit set to: %d MB", memory_limit);
    }
    
    if (setrlimit(RLIMIT_DATA, &lim) == -1) {
        debug_print("Failed to set data segment limit: %s", strerror(errno));
    }
    
    // Set file size limit
    lim.rlim_cur = lim.rlim_max = 64 * STD_MB;  // 64MB file size limit
    if (setrlimit(RLIMIT_FSIZE, &lim) == -1) {
        debug_print("Failed to set file size limit: %s", strerror(errno));
    } else {
        debug_print("File size limit set to: 64 MB");
    }
    
    // Set stack size limit
    lim.rlim_cur = lim.rlim_max = 256 * STD_MB;  // 8MB stack limit
    if (setrlimit(RLIMIT_STACK, &lim) == -1) {
        debug_print("Failed to set stack size limit: %s", strerror(errno));
    } else {
        debug_print("Stack size limit set to: 256 MB");
    }
}

// Drop privileges to non-privileged user
void drop_privileges() {
    debug_print("Starting to drop privileges");
    
    // Set group ID
    if (setgid(JUDGE_GID) != 0) {
        debug_print("Failed to set GID: %s", strerror(errno));
        exit(OJ_RE);
    }
    
    // Set user ID
    if (setuid(JUDGE_UID) != 0) {
        debug_print("Failed to set UID: %s", strerror(errno));
        exit(OJ_RE);
    }
    
    debug_print("Privilege dropping successful: UID=%d, GID=%d", JUDGE_UID, JUDGE_GID);
}

// Get process status information
int get_proc_status(int pid, const char *mark) {
    FILE *pf;
    char fn[BUFFER_SIZE], buf[BUFFER_SIZE];
    int ret = 0;
    snprintf(fn, sizeof(fn), "/proc/%d/status", pid);
    pf = fopen(fn, "r");
    int m = strlen(mark);
    while (pf && fgets(buf, BUFFER_SIZE - 1, pf)) {
        buf[strlen(buf) - 1] = 0;
        if (strncmp(buf, mark, m) == 0) {
            if (1 != sscanf(buf + m + 1, "%d", &ret)) {
                debug_print("Failed to read process status");
            }
        }
    }
    if (pf) fclose(pf);
    return ret;
}

// Get memory usage
int get_page_fault_mem(struct rusage &ruse, pid_t &pidApp) {
    int m_minflt = ruse.ru_minflt * getpagesize();
    if (DEBUG) {
        static int last_memory = 0;
        // Output debug information only when memory changes by more than 10MB
        if (abs(m_minflt - last_memory) > 10 * 1024 * 1024) {
            int m_vmpeak = get_proc_status(pidApp, "VmPeak:");
            int m_vmdata = get_proc_status(pidApp, "VmData:");
            debug_print("Memory usage: VmPeak:%d KB VmData:%d KB minflt:%d KB", 
                       m_vmpeak, m_vmdata, m_minflt >> 10);
            last_memory = m_minflt;
        }
    }
    return m_minflt;
}

// Print runtime error information
void print_runtimeerror(const char* infile, const char *err) {
    debug_print("Runtime error: %s: %s", infile, err);
}

// Modify escape function for strings
void escape_json_string(const char* input, char* output, size_t max_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < max_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        
        // Handle UTF-8 multibyte characters
        if (c >= 0x80) {
            // Check if there's enough space to store this character
            if (j < max_size - 1) {
                output[j++] = c;
            }
            continue;
        }
        
        // Handle ASCII control characters and special characters
        switch (c) {
            case '\\':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = '\\';
                }
                break;
            case '\"':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = '\"';
                }
                break;
            case '\n':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = 'n';
                }
                break;
            case '\r':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = 'r';
                }
                break;
            case '\t':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = 't';
                }
                break;
            case '\b':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = 'b';
                }
                break;
            case '\f':
                if (j < max_size - 2) {
                    output[j++] = '\\';
                    output[j++] = 'f';
                }
                break;
            case ' ': // Explicitly handle spaces, ensuring they're preserved
                output[j++] = c;
                break;
            default:
                if (c < 32) {
                    // Handle other control characters
                    if (j < max_size - 6) {
                        snprintf(output + j, 7, "\\u%04x", c);
                        j += 6;
                    }
                } else {
                    output[j++] = c;
                }
        }
    }
    output[j] = '\0';
}

// Modify single JSON output function, add control for whether to add comma
void output_json_item(const char* input, const char* output, const char* expected_output, const char* error, const char* traceback, const char* status, bool is_last) {
    char* escaped_input = NULL;
    char* escaped_output = NULL;
    char* escaped_expected = NULL;
    char* escaped_error = NULL;
    char* escaped_traceback = NULL;
    
    if (input && strlen(input) > 0) {
        escaped_input = (char*)malloc(MAX_OUTPUT_SIZE);
        if (escaped_input) {
            escape_json_string(input, escaped_input, MAX_OUTPUT_SIZE);
        }
    }
    
    // Process output, no longer restricted to only showing on success
    if (output && strlen(output) > 0) {
        escaped_output = (char*)malloc(MAX_OUTPUT_SIZE);
        if (escaped_output) {
            escape_json_string(output, escaped_output, MAX_OUTPUT_SIZE);
        }
    }
    
    // Add handling for expected output
    if (expected_output && strlen(expected_output) > 0) {
        escaped_expected = (char*)malloc(MAX_OUTPUT_SIZE);
        if (escaped_expected) {
            escape_json_string(expected_output, escaped_expected, MAX_OUTPUT_SIZE);
        }
    }
    
    if (error && strlen(error) > 0) {
        escaped_error = (char*)malloc(MAX_OUTPUT_SIZE);
        if (escaped_error) {
            escape_json_string(error, escaped_error, MAX_OUTPUT_SIZE);
        }
    }
    
    if (traceback && strlen(traceback) > 0) {
        escaped_traceback = (char*)malloc(MAX_OUTPUT_SIZE);
        if (escaped_traceback) {
            escape_json_string(traceback, escaped_traceback, MAX_OUTPUT_SIZE);
        }
    }
    
    printf("  {\n");
    
    // Output input only when it's not empty
    if (input && strlen(input) > 0 && escaped_input) {
        printf("    \"input\": \"%s\",\n", escaped_input);
    }
    
    // Output can be null or string, no longer restricted to only showing on success
    if (escaped_output) {
        printf("    \"output\": \"%s\",\n", escaped_output);
    } else {
        printf("    \"output\": null,\n");
    }
    
    // Add expected output field
    if (expected_output && strlen(expected_output) > 0 && escaped_expected) {
        printf("    \"expected_output\": \"%s\",\n", escaped_expected);
    } else {
        printf("    \"expected_output\": null,\n");
    }
    
    // Add result field
    if (output) {  // Attempt to display result if there's any output
        if (strcmp(status, "success") == 0) {
            // Successfully ran, display AC
            printf("    \"result\": \"AC\",\n");
        } else if (strcmp(status, "wrong_answer") == 0) {
            // Wrong answer, display WA
            printf("    \"result\": \"WA\",\n");
        } else if (strstr(status, "error") || strstr(status, "exceeded")) {
            // Various errors or exceeded limits, display RE
            printf("    \"result\": \"RE\",\n");
        } else {
            // Other cases, display NO_CHECK
            printf("    \"result\": \"NO_CHECK\",\n");
        }
    } else {
        printf("    \"result\": null,\n");
    }
    
    // error and traceback are null, output null
    if (error && strlen(error) > 0 && escaped_error) {
        printf("    \"error\": \"%s\",\n", escaped_error);
    } else {
        printf("    \"error\": null,\n");
    }
    
    if (traceback && strlen(traceback) > 0 && escaped_traceback) {
        printf("    \"traceback\": \"%s\",\n", escaped_traceback);
    } else {
        printf("    \"traceback\": null,\n");
    }
    
    printf("    \"status\": \"%s\"\n", status);
    printf("  }%s\n", is_last ? "" : ",");

    // Free memory
    free(escaped_input);
    free(escaped_output);
    free(escaped_expected);
    free(escaped_error);
    free(escaped_traceback);
}

// Add new array output function
void output_json_array(const std::vector<std::string>& inputs, const std::vector<std::string>& outputs, 
                     const std::vector<std::string>& expected_outputs,
                     const std::vector<std::string>& errors, const std::vector<std::string>& tracebacks, 
                     const std::vector<std::string>& statuses) {
    printf("[\n");
    
    int min_size = std::min(inputs.size(), statuses.size());
    for (size_t i = 0; i < min_size; i++) {
        const char* input = inputs[i].c_str();
        // Get status
        const char* status = i < statuses.size() ? statuses[i].c_str() : "unknown";
        // Get output, only passed in AC and WA states
        const char* output = NULL;
        if (i < outputs.size() && 
            (strcmp(status, "success") == 0 || strcmp(status, "wrong_answer") == 0)) {
            output = outputs[i].c_str();
        }
        // Get expected output
        const char* expected_output = (i < expected_outputs.size()) ? expected_outputs[i].c_str() : NULL;
        const char* error = i < errors.size() ? errors[i].c_str() : NULL;
        const char* traceback = i < tracebacks.size() ? tracebacks[i].c_str() : NULL;
        
        // Last item doesn't add a comma
        bool is_last = (i == min_size - 1);
        output_json_item(input, output, expected_output, error, traceback, status, is_last);
    }
    printf("]\n");
}

// Parse input string into multiple input items
std::vector<std::string> parse_input_list(const char* input_list) {
    std::vector<std::string> result;
    if (!input_list || strlen(input_list) == 0) {
        return result;
    }
    
    debug_print("Starting to parse input list: %s", input_list);
    
    // Parse Python-style list string ['item1', 'item2', 'item3']
    const char* p = input_list;
    
    // Skip leading whitespace characters
    while (*p && isspace(*p)) p++;
    
    // Check if it starts with [
    if (*p == '[') {
        p++; // Skip [
    } else {
        // Not a list format, treat the entire input as a single item
        result.push_back(input_list);
        return result;
    }
    
    // Parse list items
    bool in_string = false;    // Whether inside a string
    bool escaped = false;      // Whether escaping a character
    int nested_level = 0;      // Nesting level, used for handling nested lists
    std::string current;       // Current item being parsed
    char string_quote = 0;     // Type of quote used for strings (' or ")
    
    while (*p) {
        char c = *p++;
        
        if (escaped) {
            // Handle escaped characters
            if (c == 'n') {
                current += '\n'; // Handle \n
            } else if (c == 't') {
                current += '\t'; // Handle \t
            } else if (c == 'r') {
                current += '\r'; // Handle \r
            } else {
                current += c;   // Other escaped characters, handled as-is
            }
            escaped = false;
        } else if (c == '\\') {
            // Escape symbol
            escaped = true;
        } else if ((c == '\'' || c == '\"') && (!in_string || c == string_quote)) {
            // Start or end of string
            if (!in_string) {
                string_quote = c; // Record the type of quote used
                in_string = true;
            } else {
                in_string = false;
                string_quote = 0;
            }
        } else if (!in_string && c == '[') {
            // Start of nested list
            nested_level++;
            current += c;
        } else if (!in_string && c == ']') {
            // End of nested list or main list
            if (nested_level > 0) {
                nested_level--;
                current += c;
            } else {
                // Main list ended, add current item if there is one
                if (!current.empty()) {
                    result.push_back(current);
                }
                break;
            }
        } else if (!in_string && c == ',' && nested_level == 0) {
            // Found item separator, add current item to result
            result.push_back(current);
            current.clear();
            
            // Skip whitespace characters after comma
            while (*p && isspace(*p)) {
                p++;
            }
        } else {
            // Regular character
            current += c;
        }
    }
    
    // Clean up string (smart handling of spaces and quotes)
    for (auto& item : result) {
        // Remove trailing spaces
        size_t end = item.length();
        while (end > 0 && isspace(item[end-1])) {
            end--;
        }
        item = item.substr(0, end);
        
        // Remove leading and trailing quotes (if any)
        if (item.length() >= 2) {
            if ((item[0] == '\'' && item[item.length()-1] == '\'') || 
                (item[0] == '\"' && item[item.length()-1] == '\"')) {
                item = item.substr(1, item.length() - 2);
                // String content, all spaces preserved, no further processing
                continue;
            }
        }
        
        // Check if it's a pure number (including decimals and negative numbers)
        bool is_numeric = true;
        bool has_dot = false;
        size_t start_pos = 0;
        
        // Skip leading spaces to check for numbers
        while (start_pos < item.length() && isspace(item[start_pos])) {
            start_pos++;
        }
        
        if (start_pos < item.length()) {
            // Check for negative sign
            size_t check_pos = start_pos;
            if (item[check_pos] == '-' || item[check_pos] == '+') {
                check_pos++;
            }
            
            // Check for number part
            for (size_t i = check_pos; i < item.length(); i++) {
                char c = item[i];
                if (isspace(c)) {
                    // Spaces in the middle or end of the number, skipped (will be cleaned up later)
                    continue;
                } else if (isdigit(c)) {
                    // Normal number character
                    continue;
                } else if (c == '.' && !has_dot) {
                    // Decimal point, only one allowed
                    has_dot = true;
                    continue;
                } else {
                    // Other characters, not pure numbers
                    is_numeric = false;
                    break;
                }
            }
        } else {
            // All spaces, not a number
            is_numeric = false;
        }
        
        // If it's a pure number, remove leading and trailing spaces
        if (is_numeric) {
            size_t start = 0;
            while (start < item.length() && isspace(item[start])) {
                start++;
            }
            
            size_t end = item.length();
            while (end > start && isspace(item[end-1])) {
                end--;
            }
            
            item = item.substr(start, end - start);
        }
        // If it's not a pure number, keep the original format (just removed trailing spaces)
    }
    
    debug_print("Parsing completed, found %zu input items", result.size());
    for (size_t i = 0; i < result.size() && i < 3; i++) {
        debug_print("Input item %zu: '%s'%s", i, 
                 result[i].substr(0, 30).c_str(), 
                 (result[i].length() > 30 ? "..." : ""));
    }
    
    return result;
}

// Add signal handler
void timeout_handler(int signo) {
    debug_print("Received SIGALRM signal");
    exit(OJ_TL);
}

// Helper function: Remove trailing whitespace characters (including newline)
std::string trim_trailing_whitespace(const std::string& str) {
    size_t end = str.find_last_not_of(" \t\n\r");
    if (end == std::string::npos) {
        return "";  // String is all whitespace characters
    }
    return str.substr(0, end + 1);
}

// Add new function: Remove leading empty lines
std::string trim_leading_empty_lines(const std::string& str) {
    std::istringstream stream(str);
    std::string line;
    std::ostringstream result;
    bool found_non_empty = false;
    
    while (std::getline(stream, line)) {
        // Check if current line is empty (only contains spaces, tabs, or completely empty)
        bool is_empty_line = true;
        for (char c : line) {
            if (c != ' ' && c != '\t') {
                is_empty_line = false;
                break;
            }
        }
        
        if (!is_empty_line || found_non_empty) {
            // If it's not an empty line, or we've already found a non-empty line, keep this line
            if (found_non_empty) {
                result << '\n';
            }
            result << line;
            found_non_empty = true;
        }
    }
    
    return result.str();
}

// Add new function: Remove leading spaces and tabs from each line
std::string trim_leading_spaces(const std::string& str) {
    std::istringstream stream(str);
    std::string line;
    std::ostringstream result;
    bool first_line = true;
    
    while (std::getline(stream, line)) {
        // Remove leading spaces and tabs from the start of the line
        size_t start = line.find_first_not_of(" \t");
        if (start != std::string::npos) {
            line = line.substr(start);
        } else {
            // If the entire line is spaces, clear it
            line.clear();
        }
        
        if (!first_line) {
            result << '\n';
        }
        result << line;
        first_line = false;
    }
    
    return result.str();
}

void trim_line_ends(std::string& s) {
    std::istringstream stream(s);
    std::string line;
    std::ostringstream result;
    bool first_line = true;
    
    while (std::getline(stream, line)) {
        // Remove trailing spaces and tabs from the end of the line
        size_t end = line.find_last_not_of(" \t");
        if (end != std::string::npos) {
            line = line.substr(0, end + 1);
        } else {
            // If the entire line is spaces, clear it
            line.clear();
        }
        
        if (!first_line) {
            result << '\n';
        }
        result << line;
        first_line = false;
    }
    
    s = result.str();
}

// Compare user output with expected output - optimized C++ implementation
int compare_outputs(const std::string& output, const std::string& expected_output) {
    debug_print("Starting to compare outputs (C++ optimized version)");
    
    // Preprocessing: Remove trailing spaces but keep leading spaces
    std::string trimmed_output = output;
    std::string trimmed_expected = expected_output;
    
    trim_line_ends(trimmed_output);
    trim_line_ends(trimmed_expected);
    
    // Remove leading empty lines
    trimmed_output = trim_leading_empty_lines(trimmed_output);
    trimmed_expected = trim_leading_empty_lines(trimmed_expected);
    
    // Remove leading spaces and tabs from each line
    trimmed_output = trim_leading_spaces(trimmed_output);
    trimmed_expected = trim_leading_spaces(trimmed_expected);
    
    // Further processing: Remove trailing whitespace characters (including newline)
    // This allows us to ignore differences in the last newline character
    trimmed_output = trim_trailing_whitespace(trimmed_output);
    trimmed_expected = trim_trailing_whitespace(trimmed_expected);
    
    debug_print("Length of processed output: user %zu, expected %zu", 
                trimmed_output.length(), trimmed_expected.length());
    
    // Perform string comparison directly
    if (trimmed_output == trimmed_expected) {
        debug_print("Outputs match (AC)");
        return OJ_AC;
    } else {
        debug_print("Outputs don't match (WA)");
        
        // Optional: Output debug information to show where the difference is (only in debug mode)
        if (DEBUG) {
            size_t min_len = std::min(trimmed_output.length(), trimmed_expected.length());
            size_t diff_pos = min_len;  // Default difference at the end
            
            // Find the position of the first different character
            for (size_t i = 0; i < min_len; ++i) {
                if (trimmed_output[i] != trimmed_expected[i]) {
                    diff_pos = i;
                    break;
                }
            }
            
            if (diff_pos < min_len) {
                debug_print("First difference at position: %zu, user output: '%c' (0x%02x), expected output: '%c' (0x%02x)", 
                           diff_pos, 
                           trimmed_output[diff_pos], (unsigned char)trimmed_output[diff_pos],
                           trimmed_expected[diff_pos], (unsigned char)trimmed_expected[diff_pos]);
            } else {
                debug_print("Different lengths: user output %zu characters, expected output %zu characters", 
                           trimmed_output.length(), trimmed_expected.length());
            }
            
            // Display the first few lines of content for debugging
            const size_t preview_len = 200;
            if (trimmed_output.length() > preview_len || trimmed_expected.length() > preview_len) {
                debug_print("User output first %zu characters: %.200s%s", 
                           preview_len, trimmed_output.c_str(),
                           trimmed_output.length() > preview_len ? "..." : "");
                debug_print("Expected output first %zu characters: %.200s%s", 
                           preview_len, trimmed_expected.c_str(),
                           trimmed_expected.length() > preview_len ? "..." : "");
            }
            
            // Check if it's just a difference in trailing whitespace characters
            std::string orig_output_trimmed = trim_trailing_whitespace(output);
            std::string orig_expected_trimmed = trim_trailing_whitespace(expected_output);
            if (orig_output_trimmed == orig_expected_trimmed) {
                debug_print("Note: Output content is the same except for trailing whitespace (ignored)");
            }
        }
        
        return OJ_WA;
    }
}

// Add new function: Parse JSON dictionary
bool parse_json_input(const char* json_str, std::vector<std::string>& inputs, std::vector<std::string>& expected_outputs) {
    debug_print("Starting to parse JSON input");
    
    // Clear input containers
    inputs.clear();
    expected_outputs.clear();
    
    if (!json_str || strlen(json_str) == 0) {
        debug_print("JSON string is empty");
        return false;
    }
    
    // Try to recognize different JSON formats
    // First, remove leading and trailing whitespace characters
    const char* p = json_str;
    while (*p && isspace(*p)) p++;
    
    // Check if it starts with {
    if (*p != '{') {
        debug_print("JSON is not an object starting with {");
        return false;
    }
    
    // Output the first few characters for debugging
    char debug_prefix[50];
    strncpy(debug_prefix, p, 49);
    debug_prefix[49] = '\0';
    debug_print("JSON prefix: %s", debug_prefix);
    
    // Find "input" or "inputs" field, support single quotes and double quotes
    const char* input_key = strstr(p, "\"input\"");
    if (!input_key) input_key = strstr(p, "\"inputs\"");
    if (!input_key) input_key = strstr(p, "'input'");
    if (!input_key) input_key = strstr(p, "'inputs'");
    
    const char* output_key = strstr(p, "\"output\"");
    if (!output_key) output_key = strstr(p, "\"outputs\"");
    if (!output_key) output_key = strstr(p, "'output'");
    if (!output_key) output_key = strstr(p, "'outputs'");
    
    if (!input_key || !output_key) {
        debug_print("JSON doesn't contain input/inputs or output/outputs fields");
        return false;
    }
    
    debug_print("Found input and output fields");
    
    // Find the start of the list '['
    const char* inputs_start = strchr(input_key, '[');
    const char* outputs_start = strchr(output_key, '[');
    
    if (!inputs_start || !outputs_start) {
        debug_print("JSON doesn't contain start marker '[' for list");
        return false;
    }
    
    // Find the end of the list ']'
    const char* inputs_end = find_matching_bracket(inputs_start);
    const char* outputs_end = find_matching_bracket(outputs_start);
    
    if (!inputs_end || !outputs_end) {
        debug_print("JSON doesn't contain end marker ']' for list");
        return false;
    }
    
    debug_print("Successfully located input and output arrays");
    
    // Extract input list string
    size_t inputs_len = inputs_end - inputs_start + 1;
    char* inputs_list = (char*)malloc(inputs_len + 1);
    if (!inputs_list) {
        debug_print("Memory allocation failed");
        return false;
    }
    strncpy(inputs_list, inputs_start, inputs_len);
    inputs_list[inputs_len] = '\0';
    
    // Extract output list string
    size_t outputs_len = outputs_end - outputs_start + 1;
    char* outputs_list = (char*)malloc(outputs_len + 1);
    if (!outputs_list) {
        debug_print("Memory allocation failed");
        free(inputs_list);
        return false;
    }
    strncpy(outputs_list, outputs_start, outputs_len);
    outputs_list[outputs_len] = '\0';
    
    debug_print("Extracted input array: %s", inputs_list);
    debug_print("Extracted output array: %s", outputs_list);
    
    // Parse input list
    inputs = parse_input_list(inputs_list);
    
    // Parse output list
    expected_outputs = parse_input_list(outputs_list);
    
    free(inputs_list);
    free(outputs_list);
    
    debug_print("Parsed JSON successfully, found %zu input items and %zu expected outputs", 
                inputs.size(), expected_outputs.size());
    
    return (inputs.size() > 0 || expected_outputs.size() > 0);
}

// Helper function: Find matching brackets
const char* find_matching_bracket(const char* start) {
    if (*start != '[') return NULL;
    
    int count = 1;  // Found one left bracket
    const char* p = start + 1;
    
    while (*p && count > 0) {
        if (*p == '[') {
            count++;
        } else if (*p == ']') {
            count--;
        } else if (*p == '\"') {
            // Skip double-quoted string content
            p++;
            while (*p && *p != '\"') {
                if (*p == '\\' && *(p+1)) p++; // Skip escape character
                p++;
            }
            if (!*p) break; // String not closed
        } else if (*p == '\'') {
            // Skip single-quoted string content
            p++;
            while (*p && *p != '\'') {
                if (*p == '\\' && *(p+1)) p++; // Skip escape character
                p++;
            }
            if (!*p) break; // String not closed
        }
        
        if (count == 0) return p;
        p++;
    }
    
    return (count == 0) ? p : NULL;
}

// Set file system security isolation and network isolation (permission restriction mode)
void setup_process_isolation(const char* local_sandbox_dir) {
    debug_print("Setting file system security isolation (permission restriction mode)");
    
    // Use parent process's sandbox directory
    if (!local_sandbox_dir || strlen(local_sandbox_dir) == 0) {
        debug_print("Parent process didn't create sandbox directory, skipping file system isolation");
        return;
    }
    
    debug_print("Using sandbox directory: %s", local_sandbox_dir);
    
    // Check current process's permissions
    uid_t current_uid = getuid();
    uid_t effective_uid = geteuid();
    
    debug_print("Current user permissions: UID=%d, EUID=%d", current_uid, effective_uid);
    
    // Switch to sandbox directory as working directory
    if (chdir(local_sandbox_dir) != 0) {
        debug_print("Failed to switch to sandbox directory: %s", strerror(errno));
        return;
    }
    debug_print("Successfully switched to sandbox directory");
    
    // Set umask to restrict file creation permissions
    mode_t old_umask = umask(0022);  // Only allow owner to write
    debug_print("Set umask to 0022, restricting file creation permissions");
    
    // Use unshare to create new file system namespace (if possible)
    if (unshare(CLONE_NEWNS) == 0) {
        debug_print("Successfully created new file system namespace");
        
        // Mount root file system as read-only
        if (mount("/", "/", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == 0) {
            debug_print("Successfully set root file system to read-only");
        } else {
            debug_print("Failed to set root file system to read-only: %s", strerror(errno));
        }
        
        // Mount current sandbox directory as read-write
        if (mount(local_sandbox_dir, local_sandbox_dir, NULL, MS_BIND | MS_REMOUNT, NULL) == 0) {
            debug_print("Sandbox directory kept with read-write permissions");
        } else {
            debug_print("Failed to remount sandbox directory: %s", strerror(errno));
        }
        
        // Mount /tmp directory as read-only (to prevent writing to /tmp)
        if (mount("/tmp", "/tmp", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == 0) {
            debug_print("Set /tmp directory to read-only");
        } else {
            debug_print("Failed to set /tmp directory to read-only: %s", strerror(errno));
        }
        
    } else {
        debug_print("Failed to create new file system namespace using unshare");
    }

    // Network isolation (aligned with judge_client.cc line 2654)
    debug_print("Setting network isolation");
    if (unshare(CLONE_NEWNET) == 0) {   
        debug_print("Network isolation successful");
    } else {
        debug_print("Failed to set network isolation: %s", strerror(errno));
    }
    
    debug_print("File system permission restriction settings completed");
}

// Unified temporary file cleanup function (aligned with judge_client.cc's clean_workdir logic)
void cleanup_temp_files(const char* temp_path, const char* stdin_path, const char* stdout_path, 
                       const char* stderr_path, bool has_input) {
    debug_print("Starting to clean up temporary files");
    
    if (DEBUG) {
        // Debug mode: Keep files in /tmp/judge_debug directory (aligned with judge_client.cc's debug logic)
        char debug_dir[] = "/tmp/judge_debug";
        char timestamp[32];
        time_t now = time(NULL);
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
        
        char debug_session_dir[BUFFER_SIZE];
        snprintf(debug_session_dir, sizeof(debug_session_dir), "%s/%s_%d", debug_dir, timestamp, getpid());
        
        // Create debug directory
        if (mkdir(debug_dir, 0755) == -1 && errno != EEXIST) {
            debug_print("Failed to create debug directory: %s", strerror(errno));
        }
        if (mkdir(debug_session_dir, 0755) == -1) {
            debug_print("Failed to create debug session directory: %s", strerror(errno));
        } else {
            debug_print("Debug mode: Keeping files in %s", debug_session_dir);
            
            // Copy files to debug directory instead of deleting
            char cmd[BUFFER_SIZE];
            if (temp_path) {
                snprintf(cmd, sizeof(cmd), "cp %s %s/source_code.py 2>/dev/null", temp_path, debug_session_dir);
                system(cmd);
            }
            if (has_input && stdin_path) {
                snprintf(cmd, sizeof(cmd), "cp %s %s/input.txt 2>/dev/null", stdin_path, debug_session_dir);
                system(cmd);
            }
            if (stdout_path) {
                snprintf(cmd, sizeof(cmd), "cp %s %s/stdout.txt 2>/dev/null", stdout_path, debug_session_dir);
                system(cmd);
            }
            if (stderr_path) {
                snprintf(cmd, sizeof(cmd), "cp %s %s/stderr.txt 2>/dev/null", stderr_path, debug_session_dir);
                system(cmd);
            }
        }
    }
    
    // Delete temporary files (original files should be deleted in normal mode or after copying in debug mode)
    if (temp_path) {
        if (unlink(temp_path) == -1 && errno != ENOENT) {
            debug_print("Failed to delete source code temporary file: %s", strerror(errno));
        }
    }
    
    if (has_input && stdin_path) {
        if (unlink(stdin_path) == -1 && errno != ENOENT) {
            debug_print("Failed to delete input temporary file: %s", strerror(errno));
        }
    }
    
    if (stdout_path) {
        if (unlink(stdout_path) == -1 && errno != ENOENT) {
            debug_print("Failed to delete output temporary file: %s", strerror(errno));
        }
    }
    
    if (stderr_path) {
        if (unlink(stderr_path) == -1 && errno != ENOENT) {
            debug_print("Failed to delete error output temporary file: %s", strerror(errno));
        }
    }
    
    debug_print("Temporary files cleanup completed");
}

// Compare files cleanup function
void cleanup_compare_files(const char* user_output_file, const char* expected_output_file) {
    if (user_output_file) {
        if (unlink(user_output_file) == -1 && errno != ENOENT) {
            debug_print("Failed to delete user output comparison file: %s", strerror(errno));
        }
    }
    
    if (expected_output_file) {
        if (unlink(expected_output_file) == -1 && errno != ENOENT) {
            debug_print("Failed to delete expected output comparison file: %s", strerror(errno));
        }
    }
}

// Clean up sandbox directory function (aligned with judge_client.cc's cleanup logic)
void cleanup_sandbox_directory() {
    if (strlen(sandbox_dir) == 0) {
        debug_print("No sandbox directory to clean up");
        return;
    }
    
    debug_print("Starting to clean up sandbox directory: %s", sandbox_dir);
    
    // Unmount possible mount points (aligned with judge_client.cc's umount function)
    umount_work_directory(sandbox_dir);
    
    // Recursively delete sandbox directory and its contents (aligned with judge_client.cc's cleanup method)
    char cmd[BUFFER_SIZE];
    snprintf(cmd, sizeof(cmd), "rm -rf %s 2>/dev/null", sandbox_dir);
    if (system(cmd) == 0) {
        debug_print("Successfully cleaned up sandbox directory");
    } else {
        debug_print("Failed to clean up sandbox directory, but continuing execution");
    }
    
    // Clear sandbox directory path
    sandbox_dir[0] = '\0';
}

// Unmount working directory's mount points (aligned with judge_client.cc's umount function)
void umount_work_directory(const char* work_dir) {
    debug_print("Starting to unmount working directory's mount points: %s", work_dir);
    
    // Switch to working directory
    char original_dir[BUFFER_SIZE];
    if (getcwd(original_dir, sizeof(original_dir)) == NULL) {
        debug_print("Failed to get current directory: %s", strerror(errno));
        strncpy(original_dir, "/tmp", sizeof(original_dir) - 1);
    }
    
    if (chdir(work_dir) != 0) {
        debug_print("Failed to switch to working directory: %s", strerror(errno));
        return;
    }
    
    // Unmount various mount points (aligned with judge_client.cc's umount logic)
    char cmd[BUFFER_SIZE];
    
    // Unmount usr directory
    snprintf(cmd, sizeof(cmd), "/bin/umount -l %s/usr 2>/dev/null", work_dir);
    system(cmd);
    
    // Unmount proc directory
    if (strlen(work_dir) > 0) {
        snprintf(cmd, sizeof(cmd), "/bin/umount -l %s/proc 2>/dev/null", work_dir);
        system(cmd);
    }
    
    // Unmount dev directory
    snprintf(cmd, sizeof(cmd), "/bin/umount -l %s/dev 2>/dev/null", work_dir);
    system(cmd);
    
    // Unmount usr directory again
    snprintf(cmd, sizeof(cmd), "/bin/umount -l %s/usr 2>/dev/null", work_dir);
    system(cmd);
    
    // Unmount mount points under current directory
    system("/bin/umount -l usr dev 2>/dev/null");
    system("/bin/umount -l lib lib64 2>/dev/null");
    
    // Try to delete empty directories
    snprintf(cmd, sizeof(cmd), "/bin/rmdir %s/* 2>/dev/null", work_dir);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "/bin/rmdir %s/log/* 2>/dev/null", work_dir);
    system(cmd);
    
    // Switch back to original directory
    if (chdir(original_dir) != 0) {
        debug_print("Failed to switch back to original directory: %s", strerror(errno));
    }
    
    debug_print("Working directory mount points unmounted");
}

// Add new: Enhanced process monitoring function, completely avoiding zombie process interference

// Add new: Enhanced process monitoring function, completely avoiding zombie process interference
void enhanced_monitor_process(pid_t pidApp, double time_limit, int &ACflg, long long &topmemory, 
                            long long mem_lmt, int &usedtime, const char* infile) {
    if (!use_ptrace) {
        debug_print("ptrace monitoring disabled, skipping monitoring");
        return;
    }
    
    debug_print("Starting enhanced process monitoring PID: %d", pidApp);
    
    // Set signal mask, block SIGCHLD to avoid interference with other zombie process signals
    sigset_t sigset, oldset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &sigset, &oldset) == -1) {
        debug_print("Failed to set signal mask: %s", strerror(errno));
    }
    
    // Monitoring variables
    int status, sig, exitcode;
    struct user_regs_struct reg;
    struct rusage ruse;
    long long tempmemory = 0;
    bool first_stop = true;
    bool process_alive = true;
    bool syscall_enter = true;  // Mark whether entering system call (true=entering, false=returning)
    time_t start_time = time(NULL);
    int call_id = 0;  // System call number variable
    int syscall_count = 0;  // System call counter, used to reduce debug output frequency
    
    // Monitoring loop
    while (process_alive) {
        // Check timeout
        if (time(NULL) - start_time > time_limit + 2) {
            debug_print("Monitoring timed out, forcing process termination");
            if (ACflg == OJ_AC) ACflg = OJ_TL;
            kill(pidApp, SIGKILL);
            break;
        }
        
        // Wait for target process status change
        pid_t wait_result = wait4(pidApp, &status, __WALL, &ruse);
        
        if (wait_result == pidApp) {
            // Successfully waited for target process, immediately check status
            // Output status information only in special cases
            if (DEBUG && (WIFEXITED(status) || WIFSIGNALED(status))) {
                debug_print("wait4 successfully obtained target process status, status=0x%x", status);
            }
            
            // Immediately check if process has exited
            if (WIFEXITED(status)) {
                exitcode = WEXITSTATUS(status);
                debug_print("Child process exited normally, exit code: %d", exitcode);
                if (exitcode != 0 && ACflg == OJ_AC) {
                    ACflg = OJ_RE;
                    char error[BUFFER_SIZE];
                    snprintf(error, sizeof(error), "Non-zero return value: %d", exitcode);
                    print_runtimeerror(infile, error);
                }
                process_alive = false;
                break;
            }
            
            // Check if process was terminated by signal
            if (WIFSIGNALED(status)) {
                sig = WTERMSIG(status);
                debug_print("Child process terminated by signal: %d", sig);
                
                if (ACflg == OJ_AC) {
                    switch (sig) {
                        case SIGCHLD:
                        case SIGALRM:
                        case SIGKILL:
                        case SIGXCPU:
                            ACflg = OJ_TL;
                            usedtime += time_limit * 1000;
                            debug_print("Time exceeded: %d", usedtime);
                            break;
                        case SIGXFSZ:
                            ACflg = OJ_OL;
                            break;
                        default:
                            ACflg = OJ_RE;
                    }
                    print_runtimeerror(infile, strsignal(sig));
                }
                process_alive = false;
                break;
            }
            
        } else if (wait_result == -1) {
            if (errno == ECHILD) {
                // Child process has already been reaped or doesn't exist
                debug_print("Child process has already been reaped or doesn't exist");
                process_alive = false;
                break;
            } else {
                debug_print("wait4 failed: %s", strerror(errno));
                process_alive = false;
                break;
            }
        } else {
            // wait4 returned PID of another process, ignore and continue
            debug_print("wait4 returned PID of non-target process: %d, ignoring", wait_result);
            // Clean up this zombie process
            if (wait_result > 0) {
                int dummy_status;
                waitpid(wait_result, &dummy_status, WNOHANG);
            }
            continue;
        }
        
        // Only process target process and still running
        if (wait_result != pidApp || !process_alive) {
            continue;
        }

#ifdef __APPLE__
        // macOS platform doesn't support ptrace, this should never be reached
        debug_print("macOS platform entered ptrace processing branch unexpectedly");
        process_alive = false;
        break;
#else
        // Full ptrace handling on Linux
        // Set ptrace options for the first stop
        if (first_stop && WIFSTOPPED(status)) {
            if (ptrace(PTRACE_SETOPTIONS, pidApp, NULL, 
                       PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
                debug_print("Failed to set ptrace options: %s", strerror(errno));
            } else {
                debug_print("ptrace options set successfully");
            }
            first_stop = false;
            syscall_enter = true;  // After first continue, it will be entering system call
            // Continue after first stop
            ptrace(PTRACE_SYSCALL, pidApp, NULL, 0);
            continue;
        }
        
        // Check memory usage
        tempmemory = get_page_fault_mem(ruse, pidApp);
        if (tempmemory > topmemory) {
            topmemory = tempmemory;
        }
        
        if (topmemory > mem_lmt * STD_MB) {
            debug_print("Memory exceeded: %lld > %lld", topmemory, mem_lmt * STD_MB);
            if (ACflg == OJ_AC) ACflg = OJ_ML;
            ptrace(PTRACE_KILL, pidApp, NULL, 0);
            process_alive = false;
            break;
        }
        
        // Check if it's system call tracking (only handled in STOPPED state)
        if (WIFSTOPPED(status)) {
            int stop_signal = WSTOPSIG(status);
            
            // Check if it's system call-related stop (SIGTRAP with 0x80 bit)
            if (stop_signal == (SIGTRAP | 0x80)) {
                // Only check when entering system call, continue directly after returning
                if (syscall_enter) {
                    // Get register information
                    if (ptrace(PTRACE_GETREGS, pidApp, NULL, &reg) == -1) {
                        debug_print("Failed to get registers: %s", strerror(errno));
                        syscall_enter = !syscall_enter;  // Switch state
                        ptrace(PTRACE_SYSCALL, pidApp, NULL, 0);
                        continue;
                    }
                    
                    // Get system call number
#ifdef __x86_64__
                    call_id = ((unsigned int)reg.orig_rax) % CALL_ARRAY_SIZE;
#elif defined(__i386__)
                    call_id = ((unsigned int)reg.orig_eax) % CALL_ARRAY_SIZE;
#else
                    call_id = 0;
#endif
                    
                    // Reduce frequency of debug output
                    syscall_count++;
                    if (DEBUG && (syscall_count % 20 == 1 || call_id == 1 || call_id == 11 || call_id == 231)) {
                        debug_print("Detected entering system call: %d (attempt %d)", call_id, syscall_count);
                    }
                    
                    // Check if system call is allowed
                    if (call_counter[call_id] > 0) {
                        call_counter[call_id]--;
                        if (DEBUG && call_counter[call_id] > HOJ_MAX_LIMIT - 10) {
                            debug_print("Allowed system call %d, remaining uses: %d", call_id, call_counter[call_id]);
                        }
                    } else {
                        // Disallowed system call
                        ACflg = OJ_RE;
                        char error[BUFFER_SIZE];
                        sprintf(error,
                                "Disallowed system call: %d\n"
                                "Please contact the administrator to add this system call number to the whitelist\n",
                                call_id);
                        debug_print("Runtime error: %s: %s", infile, error);
                        print_runtimeerror(infile, error);
                        ptrace(PTRACE_KILL, pidApp, NULL, 0);
                        process_alive = false;
                        break;
                    }
                }
                
                // Switch between entering/returning from system call
                syscall_enter = !syscall_enter;
                
            } else {
                // Other types of stop (signals, breakpoints, etc.)
                if (DEBUG) {
                    debug_print("Non-system call stop, signal: %d, continuing execution", stop_signal);
                }
                
                // Check if it's a fatal signal
                if (stop_signal == SIGSEGV || stop_signal == SIGFPE || stop_signal == SIGBUS || 
                    stop_signal == SIGILL || stop_signal == SIGABRT) {
                    // Fatal signal, set as runtime error and stop monitoring
                    debug_print("Detected fatal signal: %d, setting as runtime error", stop_signal);
                    if (ACflg == OJ_AC) {
                        ACflg = OJ_RE;
                        char error[BUFFER_SIZE];
                        snprintf(error, sizeof(error), "Runtime error: %s", strsignal(stop_signal));
                        print_runtimeerror(infile, error);
                    }
                    ptrace(PTRACE_KILL, pidApp, NULL, 0);
                    process_alive = false;
                    break;
                }
                
                // Continue execution, deliver fatal signal
                int signal_to_deliver = 0;
                if (stop_signal == SIGTERM || stop_signal == SIGKILL || 
                    stop_signal == SIGSTOP || stop_signal == SIGCONT) {
                    signal_to_deliver = stop_signal;
                    debug_print("Delivering signal: %d", signal_to_deliver);
                }
                
                // Continue execution
                ptrace(PTRACE_SYSCALL, pidApp, NULL, signal_to_deliver);
                continue;
            }
            
            // Continue execution
            ptrace(PTRACE_SYSCALL, pidApp, NULL, 0);
        } else {
            // Not in STOPPED state, something is wrong, exit loop
            debug_print("Unexpected process state, exiting monitoring loop");
            process_alive = false;
            break;
        }
#endif
    }
    
    // Ensure process is terminated
    kill(pidApp, SIGKILL);
    
    // Restore signal mask
    sigprocmask(SIG_SETMASK, &oldset, NULL);
    
    // Last attempt to collect resource usage
    if (wait4(pidApp, NULL, WNOHANG, &ruse) == pidApp || errno == ECHILD) {
        usedtime += (ruse.ru_utime.tv_sec * 1000 + ruse.ru_utime.tv_usec / 1000);
        usedtime += (ruse.ru_stime.tv_sec * 1000 + ruse.ru_stime.tv_usec / 1000);
    }
    
    debug_print("Enhanced process monitoring completed, total time: %d ms", usedtime);
}

int detect_language(const char* source_code) {
    debug_print("Starting to detect language...");
    
    // C++ feature detection
    if (strstr(source_code, "#include") != NULL) {
        // Check for C++ specific header files
        if (strstr(source_code, "#include <iostream>") != NULL ||
            strstr(source_code, "#include <vector>") != NULL ||
            strstr(source_code, "#include <string>") != NULL ||
            strstr(source_code, "#include <algorithm>") != NULL ||
            strstr(source_code, "std::") != NULL ||
            strstr(source_code, "cout") != NULL ||
            strstr(source_code, "cin") != NULL ||
            strstr(source_code, "namespace std") != NULL ||
            strstr(source_code, "using namespace") != NULL) {
            debug_print("Detected C++ features, identified as C++ language");
            return LANG_CPP;
        }
        // Check for C language features
        if (strstr(source_code, "#include <stdio.h>") != NULL ||
            strstr(source_code, "printf") != NULL ||
            strstr(source_code, "scanf") != NULL) {
            debug_print("Detected C language features, identified as C language");
            return LANG_C;
        }
    }
    
    // Python feature detection
    if (strstr(source_code, "import ") != NULL ||
        strstr(source_code, "def ") != NULL ||
        strstr(source_code, "if __name__ == \"__main__\":") != NULL ||
        strstr(source_code, "print(") != NULL ||
        strstr(source_code, "input(") != NULL ||
        strstr(source_code, "len(") != NULL) {
        debug_print("Detected Python features, identified as Python language");
        return LANG_PYTHON;
    }
    
    // Default to recognizing Python
    debug_print("No clear features detected, default to Python language");
    return LANG_PYTHON;
}

int compile_cpp_code(const char* source_code, char* executable_path, char* error_output) {
    debug_print("Starting to compile C++ code");
    
    // Create temporary file to save source code
    char source_path[BUFFER_SIZE];
    if (strlen(sandbox_dir) > 0) {
        snprintf(source_path, sizeof(source_path), "%s/temp_source_XXXXXX.cpp", sandbox_dir);
        debug_print("Creating C++ source file inside sandbox directory");
    } else {
        strcpy(source_path, "/tmp/temp_source_XXXXXX.cpp");
        debug_print("Sandbox directory not set, creating C++ source file in /tmp");
    }
    
    int source_fd = mkstemps(source_path, 4);
    if (source_fd == -1) {
        debug_print("Failed to create source code temporary file: %s", strerror(errno));
        snprintf(error_output, BUFFER_SIZE, "Failed to create source code temporary file: %s", strerror(errno));
        return OJ_RE;
    }
    
    // Write source code
    if (write(source_fd, source_code, strlen(source_code)) == -1) {
        close(source_fd);
        unlink(source_path);
        snprintf(error_output, BUFFER_SIZE, "Compilation error: Failed to write to source file");
        return OJ_CE;
    }
    close(source_fd);
    
    // Create executable file path
    if (strlen(sandbox_dir) > 0) {
        snprintf(executable_path, BUFFER_SIZE, "%s/cpp_exec_XXXXXX", sandbox_dir);
        debug_print("Creating executable file inside sandbox directory");
    } else {
        strcpy(executable_path, "/tmp/cpp_exec_XXXXXX");
        debug_print("Sandbox directory not set, creating executable file in /tmp");
    }
    
    int exec_fd = mkstemp(executable_path);
    if (exec_fd == -1) {
        unlink(source_path);
        snprintf(error_output, BUFFER_SIZE, "Compilation error: Failed to create temporary executable file");
        return OJ_CE;
    }
    close(exec_fd);
    
    // Create compilation command
    char compile_cmd[1024];
    snprintf(compile_cmd, sizeof(compile_cmd), 
             "g++ -O2 -std=c++17 -o %s %s 2>&1", 
             executable_path, source_path);
    
    debug_print("Executing compilation command: %s", compile_cmd);
    
    // Execute compilation
    FILE* compile_process = popen(compile_cmd, "r");
    if (!compile_process) {
        unlink(source_path);
        unlink(executable_path);
        snprintf(error_output, BUFFER_SIZE, "Compilation error: Failed to start compiler");
        return OJ_CE;
    }
    
    // Read compilation error output
    char compile_error[BUFFER_SIZE] = {0};
    size_t error_len = fread(compile_error, 1, BUFFER_SIZE - 1, compile_process);
    int compile_result = pclose(compile_process);
    
    // Clean up source file
    unlink(source_path);
    
    if (compile_result != 0) {
        unlink(executable_path);
        snprintf(error_output, BUFFER_SIZE, "Compilation error: %s", compile_error);
        debug_print("Compilation failed: %s", compile_error);
        return OJ_CE;
    }
    
    // Set executable permissions
    chmod(executable_path, 0755);
    
    debug_print("Compilation successful, executable file: %s", executable_path);
    return OJ_AC;
}

int run_executable(const char* executable_path, double time_limit, int memory_limit, const char* input, char* output, char* error) {
    debug_print("Starting to run executable file: %s", executable_path);
    debug_print("Time limit: %.1f seconds", time_limit);
    debug_print("Memory limit: %d MB", memory_limit);
    if (input) {
        debug_print("Input data length: %zu bytes", strlen(input));
    }
    
    // Create temporary files for input, output, and error - using sandbox directory
    char stdin_path[BUFFER_SIZE];
    char stdout_path[BUFFER_SIZE];
    char stderr_path[BUFFER_SIZE];
    
    // If there's a sandbox directory, create temporary files within the sandbox; otherwise use /tmp
    if (strlen(sandbox_dir) > 0) {
        snprintf(stdin_path, sizeof(stdin_path), "%s/stdin_XXXXXX", sandbox_dir);
        snprintf(stdout_path, sizeof(stdout_path), "%s/stdout_XXXXXX", sandbox_dir);
        snprintf(stderr_path, sizeof(stderr_path), "%s/stderr_XXXXXX", sandbox_dir);
        debug_print("Creating temporary files inside sandbox directory");
    } else {
        strcpy(stdin_path, "/tmp/stdin_XXXXXX");
        strcpy(stdout_path, "/tmp/stdout_XXXXXX");
        strcpy(stderr_path, "/tmp/stderr_XXXXXX");
        debug_print("Sandbox directory not set, using /tmp directory");
    }
    
    int stdin_fd = -1;
    int stdout_fd = mkstemp(stdout_path);
    int stderr_fd = mkstemp(stderr_path);
    
    bool has_input = (input && strlen(input) > 0);
    
    if (has_input) {
        stdin_fd = mkstemp(stdin_path);
        if (stdin_fd == -1) {
            debug_print("Failed to create input temporary file: %s", strerror(errno));
            strcpy(error, "Failed to create input temporary file");
            if (stdout_fd != -1) { close(stdout_fd); unlink(stdout_path); }
            if (stderr_fd != -1) { close(stderr_fd); unlink(stderr_path); }
            return OJ_RE;
        }
        
        // Write input data
        if (write(stdin_fd, input, strlen(input)) != (ssize_t)strlen(input)) {
            debug_print("Failed to write input data: %s", strerror(errno));
            strcpy(error, "Failed to write input data");
            close(stdin_fd); unlink(stdin_path);
            close(stdout_fd); unlink(stdout_path);
            close(stderr_fd); unlink(stderr_path);
            return OJ_RE;
        }
        close(stdin_fd);
        
        // Set input file permissions
        if (chmod(stdin_path, 0644) == -1) {
            debug_print("Failed to set input file permissions: %s", strerror(errno));
        }
    }

    if (stdout_fd == -1 || stderr_fd == -1) {
        debug_print("Failed to create output temporary file: %s", strerror(errno));
        strcpy(error, "Failed to create output temporary file");
        if (has_input) unlink(stdin_path);
        if (stdout_fd != -1) { close(stdout_fd); unlink(stdout_path); }
        if (stderr_fd != -1) { close(stderr_fd); unlink(stderr_path); }
        return OJ_RE;
    }
    
    close(stdout_fd);
    close(stderr_fd);
    
    // Set output file permissions
    if (chmod(stdout_path, 0666) == -1) {
        debug_print("Failed to set output file permissions: %s", strerror(errno));
    }
    if (chmod(stderr_path, 0666) == -1) {
        debug_print("Failed to set error file permissions: %s", strerror(errno));
    }


    if (use_ptrace) {
        init_syscalls_limits();
    }
    // Run program
    pid_t pid = fork();
    if (pid < 0) {
        debug_print("Failed to fork: %s", strerror(errno));
        strcpy(error, "Failed to fork");
        cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
        return OJ_RE;
    } else if (pid == 0) { // Child process
        debug_print("Child process starting execution");

        // Set resource limits
        set_security_limits(time_limit, memory_limit);
        
         // Enable ptrace tracking (aligned with judge_client.cc line 2655)
        if (use_ptrace) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
                debug_print("Failed to enable ptrace tracking: %s", strerror(errno));
                exit(OJ_RE);
            }
            // Set file system security isolation
            setup_process_isolation(sandbox_dir);
        }
        // Drop privileges
        drop_privileges();
        
        // Redirect standard input, output, and error
        if (has_input) {
            int input_fd = open(stdin_path, O_RDONLY);
            if (input_fd == -1 || dup2(input_fd, STDIN_FILENO) == -1) {
                debug_print("Failed to redirect standard input: %s", strerror(errno));
                _exit(OJ_RE);
            }
            close(input_fd);
        }
        
        int output_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (output_fd == -1 || dup2(output_fd, STDOUT_FILENO) == -1) {
            debug_print("Failed to redirect standard output: %s", strerror(errno));
            _exit(OJ_RE);
        }
        close(output_fd);
        
        int error_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (error_fd == -1 || dup2(error_fd, STDERR_FILENO) == -1) {
            debug_print("Failed to redirect standard error: %s", strerror(errno));
            _exit(OJ_RE);
        }
        close(error_fd);

        // Set alarm signal
        signal(SIGALRM, timeout_handler);
        alarm((int)(time_limit + 1));
        debug_print("Setting alarm: %.1f seconds", time_limit);
        
        // Run executable file
        execl(executable_path, executable_path, (char*)NULL);
        // If execl fails, exit
        _exit(OJ_RE);
    } else { // Parent process
        debug_print("Parent process waiting for child process (PID: %d)", pid);
        
        // Monitor child process
        int ACflg = OJ_AC;
        long long topmemory = 0;
        int usedtime = 0;
        
        enhanced_monitor_process(pid, time_limit, ACflg, topmemory, memory_limit * 1024 * 1024LL, usedtime, has_input ? stdin_path : NULL);
                // Wait for child process to finish
        int status;
        waitpid(pid, &status, 0);

        // Basic error checking
        if (!use_ptrace) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                if (exit_code != 0) {
                    ACflg = OJ_RE;
                    debug_print("Child process non-zero exit code: %d", exit_code);
                }
            } else if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                switch (sig) {
                    case SIGXCPU:
                    case SIGALRM:
                    case SIGKILL:
                        ACflg = OJ_TL;
                        debug_print("Time exceeded, signal: %d", sig);
                        break;
                    case SIGXFSZ:
                        ACflg = OJ_OL;
                        debug_print("Output exceeded, signal: %d", sig);
                        break;
                    default:
                        ACflg = OJ_RE;
                        debug_print("Runtime error, signal: %d", sig);
                        break;
                }
            }
        }
        
        debug_print("Child process finished, status: %d, ACflg: %d", status, ACflg);
        
        // Read output file content
        FILE* stdout_file = fopen(stdout_path, "r");
        FILE* stderr_file = fopen(stderr_path, "r");
        
        if (!stdout_file || !stderr_file) {
            debug_print("Failed to open output file: %s", strerror(errno));
            if (stdout_file) fclose(stdout_file);
            if (stderr_file) fclose(stderr_file);
            cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
            return OJ_RE;
        }
        
        // Get file size
        fseek(stdout_file, 0, SEEK_END);
        long stdout_size = ftell(stdout_file);
        fseek(stdout_file, 0, SEEK_SET);
        
        fseek(stderr_file, 0, SEEK_END);
        long stderr_size = ftell(stderr_file);
        fseek(stderr_file, 0, SEEK_SET);
        
        debug_print("Size of standard output file: %ld bytes", stdout_size);
        debug_print("Size of standard error file: %ld bytes", stderr_size);
        
        // Read file content
        if (stdout_size > 0) {
            // Ensure not to exceed buffer size
            size_t read_size = stdout_size < MAX_OUTPUT_SIZE - 1 ? stdout_size : MAX_OUTPUT_SIZE - 1;
            if (fread(output, 1, read_size, stdout_file) != read_size) {
                debug_print("Failed to read standard output file: %s", strerror(errno));
            }
            output[read_size] = '\0';
        } else {
            output[0] = '\0';
        }
        
        if (stderr_size > 0) {
            // Ensure not to exceed buffer size
            size_t read_size = stderr_size < MAX_OUTPUT_SIZE - 1 ? stderr_size : MAX_OUTPUT_SIZE - 1;
            if (fread(error, 1, read_size, stderr_file) != read_size) {
                debug_print("Failed to read standard error file: %s", strerror(errno));
            }
            error[read_size] = '\0';
        } else {
            error[0] = '\0';
        }
        
        // Close and delete temporary files
        fclose(stdout_file);
        fclose(stderr_file);
        cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
        
        // Return monitoring result
        debug_print("Program execution completed, returning result: %d", ACflg);
        return ACflg;
    }
}

// Optimized version: Use pre-created source code file
int run_with_shared_source(const char* source_file_path, double time_limit, int memory_limit, const char* input, char* output, char* error) {
    debug_print("Starting to run pre-created source code file: %s", source_file_path);
    debug_print("Time limit: %.1f seconds", time_limit);
    debug_print("Memory limit: %d MB", memory_limit);
    if (input) {
        debug_print("Input data length: %zu bytes", strlen(input));
    }
    
    // Create temporary files for input, output, and error
    char stdin_path[BUFFER_SIZE];
    char stdout_path[BUFFER_SIZE];
    char stderr_path[BUFFER_SIZE];
    
    // If there's a sandbox directory, create temporary files within the sandbox; otherwise use /tmp
    if (strlen(sandbox_dir) > 0) {
        snprintf(stdin_path, sizeof(stdin_path), "%s/stdin_XXXXXX", sandbox_dir);
        snprintf(stdout_path, sizeof(stdout_path), "%s/stdout_XXXXXX", sandbox_dir);
        snprintf(stderr_path, sizeof(stderr_path), "%s/stderr_XXXXXX", sandbox_dir);
        debug_print("Creating temporary files inside sandbox directory");
    } else {
        strcpy(stdin_path, "/tmp/stdin_XXXXXX");
        strcpy(stdout_path, "/tmp/stdout_XXXXXX");
        strcpy(stderr_path, "/tmp/stderr_XXXXXX");
        debug_print("Sandbox directory not set, using /tmp directory");
    }
    
    int stdin_fd = -1;
    int stdout_fd = mkstemp(stdout_path);
    int stderr_fd = mkstemp(stderr_path);
    
    bool has_input = (input && strlen(input) > 0);
    
    if (has_input) {
        stdin_fd = mkstemp(stdin_path);
        if (stdin_fd == -1) {
            debug_print("Failed to create input temporary file: %s", strerror(errno));
            strcpy(error, "Failed to create input temporary file");
            if (stdout_fd != -1) { close(stdout_fd); unlink(stdout_path); }
            if (stderr_fd != -1) { close(stderr_fd); unlink(stderr_path); }
            return OJ_RE;
        }
        
        // Write input data
        if (write(stdin_fd, input, strlen(input)) != (ssize_t)strlen(input)) {
            debug_print("Failed to write input data: %s", strerror(errno));
            strcpy(error, "Failed to write input data");
            close(stdin_fd); unlink(stdin_path);
            close(stdout_fd); unlink(stdout_path);
            close(stderr_fd); unlink(stderr_path);
            return OJ_RE;
        }
        close(stdin_fd);
        
        // Set input file permissions
        if (chmod(stdin_path, 0644) == -1) {
            debug_print("Failed to set input file permissions: %s", strerror(errno));
        }
    }

    if (stdout_fd == -1 || stderr_fd == -1) {
        debug_print("Failed to create output temporary file: %s", strerror(errno));
        strcpy(error, "Failed to create output temporary file");
        if (has_input) unlink(stdin_path);
        if (stdout_fd != -1) { close(stdout_fd); unlink(stdout_path); }
        if (stderr_fd != -1) { close(stderr_fd); unlink(stderr_path); }
        return OJ_RE;
    }
    
    close(stdout_fd);
    close(stderr_fd);
    
    // Set output file permissions
    if (chmod(stdout_path, 0666) == -1) {
        debug_print("Failed to set output file permissions: %s", strerror(errno));
    }
    if (chmod(stderr_path, 0666) == -1) {
        debug_print("Failed to set error file permissions: %s", strerror(errno));
    }
    
    if (use_ptrace) {
        init_syscalls_limits();
    }
    // Run program
    pid_t pid = fork();
    if (pid < 0) {
        debug_print("Failed to fork: %s", strerror(errno));
        strcpy(error, "Failed to fork");
        cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
        return OJ_RE;
    } else if (pid == 0) { // Child process
        debug_print("Child process starting execution");

        // Set resource limits
        set_security_limits(time_limit, memory_limit);
        
         // Enable ptrace tracking (aligned with judge_client.cc line 2655)
        if (use_ptrace) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
                debug_print("Failed to enable ptrace tracking: %s", strerror(errno));
                exit(OJ_RE);
            }
            // Set file system security isolation
            setup_process_isolation(sandbox_dir);
        }
        // Drop privileges
        drop_privileges();

        // Redirect standard input, output, and error
        if (has_input) {
            int input_fd = open(stdin_path, O_RDONLY);
            if (input_fd == -1 || dup2(input_fd, STDIN_FILENO) == -1) {
                debug_print("Failed to redirect standard input: %s", strerror(errno));
                _exit(OJ_RE);
            }
            close(input_fd);
        }
        
        int output_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (output_fd == -1 || dup2(output_fd, STDOUT_FILENO) == -1) {
            debug_print("Failed to redirect standard output: %s", strerror(errno));
            _exit(OJ_RE);
        }
        close(output_fd);
        
        int error_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (error_fd == -1 || dup2(error_fd, STDERR_FILENO) == -1) {
            debug_print("Failed to redirect standard error: %s", strerror(errno));
            _exit(OJ_RE);
        }
        close(error_fd);

        // Set alarm signal
        signal(SIGALRM, timeout_handler);
        alarm((int)(time_limit + 1));
        debug_print("Setting alarm: %.1f seconds", time_limit);

        // Run Python script
        execl("/usr/bin/python3", "python3", source_file_path, (char*)NULL);
        // If python3 is not available, try python
        execl("/usr/bin/python", "python", source_file_path, (char*)NULL);
        // If execl fails, exit
        debug_print("Failed to execute Python script: %s", strerror(errno));
        _exit(OJ_RE);
    } else { // Parent process
        debug_print("Parent process waiting for child process (PID: %d)", pid);
        
        // Monitor child process
        int ACflg = OJ_AC;
        long long topmemory = 0;
        int usedtime = 0;
        
        enhanced_monitor_process(pid, time_limit, ACflg, topmemory, memory_limit * 1024 * 1024LL, usedtime, has_input ? stdin_path : NULL);
        
        // Wait for child process to finish
        int status;
        waitpid(pid, &status, 0);

        // Basic error checking
        if (!use_ptrace) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                if (exit_code != 0) {
                    ACflg = OJ_RE;
                    debug_print("Child process non-zero exit code: %d", exit_code);
                }
            } else if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                switch (sig) {
                    case SIGXCPU:
                    case SIGALRM:
                    case SIGKILL:
                        ACflg = OJ_TL;
                        debug_print("Time exceeded, signal: %d", sig);
                        break;
                    case SIGXFSZ:
                        ACflg = OJ_OL;
                        debug_print("Output exceeded, signal: %d", sig);
                        break;
                    default:
                        ACflg = OJ_RE;
                        debug_print("Runtime error, signal: %d", sig);
                        break;
                }
            }
        }
        
        debug_print("Child process finished, status: %d, ACflg: %d", status, ACflg);
        
        // Read output file content
        FILE* stdout_file = fopen(stdout_path, "r");
        FILE* stderr_file = fopen(stderr_path, "r");
        
        if (!stdout_file || !stderr_file) {
            debug_print("Failed to open output file: %s", strerror(errno));
            if (stdout_file) fclose(stdout_file);
            if (stderr_file) fclose(stderr_file);
            cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
            return OJ_RE;
        }
        
        // Get file size
        fseek(stdout_file, 0, SEEK_END);
        long stdout_size = ftell(stdout_file);
        fseek(stdout_file, 0, SEEK_SET);
        
        fseek(stderr_file, 0, SEEK_END);
        long stderr_size = ftell(stderr_file);
        fseek(stderr_file, 0, SEEK_SET);
        
        debug_print("Size of standard output file: %ld bytes", stdout_size);
        debug_print("Size of standard error file: %ld bytes", stderr_size);
        
        // Read file content
        if (stdout_size > 0) {
            // Ensure not to exceed buffer size
            size_t read_size = stdout_size < MAX_OUTPUT_SIZE - 1 ? stdout_size : MAX_OUTPUT_SIZE - 1;
            if (fread(output, 1, read_size, stdout_file) != read_size) {
                debug_print("Failed to read standard output file: %s", strerror(errno));
            }
            output[read_size] = '\0';
        } else {
            output[0] = '\0';
        }
        
        if (stderr_size > 0) {
            // Ensure not to exceed buffer size
            size_t read_size = stderr_size < MAX_OUTPUT_SIZE - 1 ? stderr_size : MAX_OUTPUT_SIZE - 1;
            if (fread(error, 1, read_size, stderr_file) != read_size) {
                debug_print("Failed to read standard error file: %s", strerror(errno));
            }
            error[read_size] = '\0';
        } else {
            error[0] = '\0';
        }
        
        // Close and delete temporary files
        fclose(stdout_file);
        fclose(stderr_file);
        cleanup_temp_files("", stdin_path, stdout_path, stderr_path, has_input);
        
        // Return monitoring result
        debug_print("Program execution completed, returning result: %d", ACflg);
        return ACflg;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <source code file path> [time limit(seconds)] [memory limit(MB)] [input list file path] [stop on first error(0/1)] [security options]\n", argv[0]);
        printf("\nSupported programming languages:\n");
        printf("- Python: Automatically detect features including import, def, print(), file extension .py\n");
        printf("- C++: Automatically detect features including #include <iostream>, std::, cout, cin, file extension .cpp/.cc\n");
        printf("- C: Automatically detect features including #include <stdio.h>, printf, scanf, file extension .c\n");
        printf("\nInput list file can be one of two formats:\n");
        printf("1. JSON format: {'inputs':['input1','input2',...],'outputs':['expected output1','expected output2',...]}\n");
        printf("2. Simple list format: ['input1','input2',...]\n");
        printf("Note: Default behavior is to stop testing after the first error. To run all test cases, set the 5th parameter to 0.\n");
        printf("Security options: --debug Enable debug mode, --ptrace Enable ptrace monitoring\n");
        return 1;
    }
    
    // Parse command line arguments for security options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            DEBUG = 1;
            debug_print("Debug mode enabled");
        } else if (strcmp(argv[i], "--ptrace") == 0) {
            use_ptrace = 1;
            debug_print("ptrace monitoring enabled");
        } 
    }
    
    debug_print("Program started");
    debug_print("Security feature status: ptrace=%s", use_ptrace ? "enabled" : "disabled");
    
    // Create global sandbox directory at the beginning of program execution
    char temp_dir[] = "/tmp/judge_sandbox_XXXXXX";
    if (mkdtemp(temp_dir) != NULL) {
        strncpy(sandbox_dir, temp_dir, sizeof(sandbox_dir) - 1);
        sandbox_dir[sizeof(sandbox_dir) - 1] = '\0';
        debug_print("Created program-level sandbox directory: %s", sandbox_dir);
        
        // Set sandbox directory permissions so that the judge user can access it
        if (chmod(sandbox_dir, 0755) == -1) {
            debug_print("Failed to set sandbox directory permissions: %s", strerror(errno));
        } else {
            debug_print("Sandbox directory permissions set successfully: 0755");
        }
        
        // If the current user is root, change the directory ownership to the judge user
        if (getuid() == 0) {
            if (chown(sandbox_dir, JUDGE_UID, JUDGE_GID) == -1) {
                debug_print("Failed to set sandbox directory ownership: %s", strerror(errno));
            } else {
                debug_print("Sandbox directory ownership set successfully: UID=%d, GID=%d", JUDGE_UID, JUDGE_GID);
            }
        } else {
            debug_print("Current user is not root, skipping ownership setting");
        }
    } else {
        debug_print("Failed to create program-level sandbox directory: %s", strerror(errno));
        sandbox_dir[0] = '\0';  // Ensure it's empty, subsequent steps will skip sandbox isolation
    }
    
    char *source_code = NULL;
    char *input_list_str = NULL;
    
    // Read source code from file
    FILE* source_file = fopen(argv[1], "r");
    if (!source_file) {
        fprintf(stderr, "Failed to open source code file: %s\n", argv[1]);
        return 1;
    }
    
    debug_print("Reading source code from file: %s", argv[1]);
    
    // Get file size
    fseek(source_file, 0, SEEK_END);
    long file_size = ftell(source_file);
    fseek(source_file, 0, SEEK_SET);
    
    // Allocate memory
    source_code = (char*)malloc(file_size + 1);
    if (!source_code) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(source_file);
        return 1;
    }
    
    // Read file content
    size_t read_size = fread(source_code, 1, file_size, source_file);
    source_code[read_size] = '\0';  // Ensure string is null-terminated
    fclose(source_file);
    
    debug_print("Successfully read source code from file, length: %zu", strlen(source_code));
    
    // Set default limits and read custom values from command line arguments
    double time_limit = 5.0;   // Default 5 seconds
    int memory_limit = 1024;   // Default 1024MB
    bool stop_on_first_error = 0; // Default to not stopping after the first error
    
    debug_print("Number of command line arguments: %d", argc);
    
    // If time limit parameter is provided
    if (argc > 2) {
        double user_time_limit = atof(argv[2]);
        if (user_time_limit > 0.0) {
            time_limit = user_time_limit;
            debug_print("Using user-specified time limit: %.1f seconds", time_limit);
        } else {
            debug_print("Ignoring invalid time limit parameter, using default: %.1f seconds", time_limit);
        }
    }
    
    // If memory limit parameter is provided
    if (argc > 3) {
        int user_memory_limit = atoi(argv[3]);
        if (user_memory_limit > 0) {
            memory_limit = user_memory_limit;
            debug_print("Using user-specified memory limit: %d MB", memory_limit);
        } else {
            debug_print("Ignoring invalid memory limit parameter, using default: %d MB", memory_limit);
        }
    }
    
    // Check if 5th parameter is provided (whether to stop after the first error)
    if (argc > 5) {
        debug_print("Detected 5th parameter: %s", argv[5]);
        stop_on_first_error = (atoi(argv[5]) != 0); // Non-zero value means stop, 0 means don't stop
        debug_print("Setting stop_on_first_error = %d", stop_on_first_error);
    } else {
        debug_print("Using default setting: Stop testing after the first error");
    }
    
    // Containers to store inputs and expected outputs
    std::vector<std::string> input_list;
    std::vector<std::string> expected_outputs;
    
    // If input list file is provided
    if (argc > 4) {
        FILE* input_file = fopen(argv[4], "r");
        if (!input_file) {
            fprintf(stderr, "Failed to open input file: %s\n", argv[4]);
            free(source_code);
            return 1;
        }
        
        debug_print("Reading input data from file: %s", argv[4]);
        
        // Get file size
        fseek(input_file, 0, SEEK_END);
        long input_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);
        
        // Allocate memory
        input_list_str = (char*)malloc(input_size + 1);
        if (!input_list_str) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(input_file);
            free(source_code);
            return 1;
        }
        
        // Read file content
        size_t input_read_size = fread(input_list_str, 1, input_size, input_file);
        input_list_str[input_read_size] = '\0';  // Ensure string is null-terminated
        fclose(input_file);
        
        debug_print("Successfully read input data from file, length: %zu", strlen(input_list_str));
        
        // Try to parse JSON format
        if (!parse_json_input(input_list_str, input_list, expected_outputs)) {
            debug_print("JSON parsing failed, input file format incorrect");
            
            // Output JSON for error message
            char* escaped_input = (char*)malloc(MAX_OUTPUT_SIZE);
            if (escaped_input) {
                escape_json_string(input_list_str, escaped_input, MAX_OUTPUT_SIZE);
                printf("[\n  {\n");
                printf("    \"input\": \"%s\",\n", escaped_input);
                printf("    \"output\": null,\n");
                printf("    \"expected_output\": null,\n");
                printf("    \"result\": null,\n");
                printf("    \"error\": \"Input format error, please ensure correct JSON format: {'inputs': [...], 'outputs': [...]}\",\n");
                printf("    \"traceback\": null,\n");
                printf("    \"status\": \"format_error\"\n");
                printf("  }\n]\n");
                free(escaped_input);
            } else {
                // Memory allocation failed, output simplified version
                printf("[\n  {\n");
                printf("    \"input\": \"[Insufficient memory to display input]\",\n");
                printf("    \"output\": null,\n");
                printf("    \"expected_output\": null,\n");
                printf("    \"result\": null,\n");
                printf("    \"error\": \"Input format error, please ensure correct JSON format: {'inputs': [...], 'outputs': [...]}\",\n");
                printf("    \"traceback\": null,\n");
                printf("    \"status\": \"format_error\"\n");
                printf("  }\n]\n");
            }
            
            free(source_code);
            return 0;  // Normal return, not error code
        } else {
            debug_print("Successfully parsed JSON format, found %zu input items and %zu expected outputs", 
                       input_list.size(), expected_outputs.size());
        }
        
        free(input_list_str);  // Release input_list_str, as it's now copied to vector
    }
    
    // If no input list file is provided, set empty string
    else {
        // No input list provided
        input_list_str = strdup("");
        debug_print("No input data provided, using empty input");
        
        // Parse as simple input list
        input_list = parse_input_list(input_list_str);
        free(input_list_str);
    }
    
    // If there are no input items, add an empty input
    if (input_list.empty()) {
        input_list.push_back("");
        debug_print("Using one empty input item");
    }
    
    // Ensure expected output list is the same length as input list
    if (expected_outputs.size() < input_list.size()) {
        size_t original_size = expected_outputs.size();
        expected_outputs.resize(input_list.size());
        debug_print("Resizing expected output list from %zu to %zu", original_size, expected_outputs.size());
    }
    
    // Container to store all results
    std::vector<std::string> outputs;
    std::vector<std::string> errors;
    std::vector<std::string> tracebacks;
    std::vector<std::string> statuses;
    
    // Pre-allocate buffers to avoid repeated allocation and initialization in loop
    char* output_buffer = (char*)malloc(MAX_OUTPUT_SIZE);
    char* error_buffer = (char*)malloc(MAX_OUTPUT_SIZE);
    if (!output_buffer || !error_buffer) {
        debug_print("Failed to pre-allocate buffers");
        free(output_buffer);
        free(error_buffer);
        free(source_code);
        return 1;
    }
    debug_print("Successfully pre-allocated output buffer: %zu bytes x 2", (size_t)MAX_OUTPUT_SIZE);

    // Detect language type and pre-compile C++ code (only compile once)
    int detected_language = detect_language(source_code);
    debug_print("Detected language: %s", 
                detected_language == LANG_CPP ? "C++" : 
                detected_language == LANG_C ? "C" : "Python");
    
    char executable_path[256] = {0};
    bool is_compiled_language = false;
    
    if (detected_language == LANG_CPP || detected_language == LANG_C) {
        // C++/C language: pre-compile once
        debug_print("Detected C++/C code, starting pre-compilation...");
        is_compiled_language = true;
        
        char compile_error[BUFFER_SIZE] = {0};
        int compile_result = compile_cpp_code(source_code, executable_path, compile_error);
        
        if (compile_result != OJ_AC) {
            debug_print("Compilation failed: %s", compile_error);
            
            // If compilation fails, return compilation error for all test cases
            for (size_t i = 0; i < input_list.size(); i++) {
                outputs.push_back("");
                errors.push_back(compile_error);
                tracebacks.push_back("");
                statuses.push_back("compile_error");
            }
            
            // Output results and exit
            output_json_array(input_list, outputs, expected_outputs, errors, tracebacks, statuses);
            free(source_code);
            cleanup_sandbox_directory();
            return 0;
        }
        
        debug_print("C++/C code compiled successfully, executable file: %s", executable_path);
    }
    
    // In the test case loop before the main function, add pre-creation of source code file
    // For script languages, create shared source code files
    char shared_source_file[256] = {0};
    if (!is_compiled_language) {
        if (strlen(sandbox_dir) > 0) {
            snprintf(shared_source_file, sizeof(shared_source_file), "%s/shared_python_script_XXXXXX.py", sandbox_dir);
            debug_print("Creating shared source code file inside sandbox directory");
        } else {
            strcpy(shared_source_file, "/tmp/shared_python_script_XXXXXX.py");
            debug_print("Sandbox directory not set, creating shared source code file in /tmp");
        }
        
        int source_fd = mkstemps(shared_source_file, 3);
        if (source_fd == -1) {
            debug_print("Failed to create shared source code file: %s", strerror(errno));
            free(output_buffer);
            free(error_buffer);
            free(source_code);
            return 1;
        }
        
        // Write source code to shared file
        if (write(source_fd, source_code, strlen(source_code)) == -1) {
            debug_print("Failed to write to shared source code file: %s", strerror(errno));
            close(source_fd);
            unlink(shared_source_file);
            free(output_buffer);
            free(error_buffer);
            free(source_code);
            return 1;
        }
        close(source_fd);
        
        // Set file permissions
        if (chmod(shared_source_file, 0644) == -1) {
            debug_print("Failed to set permissions for shared source code file: %s", strerror(errno));
        }
        debug_print("Successfully created shared source code file: %s", shared_source_file);
    }
    
    // Run source code for each input item
    for (size_t i = 0; i < input_list.size(); i++) {
        debug_print("Processing input item %zu: %s", i, input_list[i].length() <= 100 ? input_list[i].c_str() : (input_list[i].substr(0, 97) + "...").c_str());
        
        // Before each test point, clean up possible zombie processes
        // if (i > 0) {
        //     debug_print("Test point %zu: Cleaning up residual processes from previous test point", i);
        //     // Use WNOHANG non-blocking way to clean up possible zombie processes
        //     int cleanup_status;
        //     while (waitpid(-1, &cleanup_status, WNOHANG) > 0) {
        //         debug_print("Cleaned up a zombie process");
        //     }
            
        //     // Re-initialize system call whitelist to ensure each test point has complete quota
        //     debug_print("Test point %zu: Re-initializing system call whitelist", i);
        // }
        
        // Re-use pre-allocated buffers, just clear the first byte as string termination marker
        output_buffer[0] = '\0';
        error_buffer[0] = '\0';
        
        // Select runtime based on language type
        int result;
        if (is_compiled_language) {
            // Run compiled executable file
            result = run_executable(executable_path, time_limit, memory_limit, input_list[i].c_str(), output_buffer, error_buffer);
        } else {
            // Use shared source code file for script languages (Python, etc.)
            result = run_with_shared_source(shared_source_file, time_limit, memory_limit, input_list[i].c_str(), output_buffer, error_buffer);
        }
        debug_print("Input item %zu execution result: %d", i, result);
        
        // Store output
        outputs.push_back(output_buffer ? std::string(output_buffer) : "");
        
        // Set error message, stack trace, and status based on result
        std::string error_str = "";
        std::string traceback_str = "";
        std::string status_str = "";
        
        switch (result) {
            case OJ_AC:
                debug_print("Input item %zu successful", i);
                status_str = "success";
                
                // Check if output matches expected output
                if (i < expected_outputs.size() && !expected_outputs[i].empty()) {
                    int compare_result = compare_outputs(outputs[i], expected_outputs[i]);
                    if (compare_result == OJ_AC) {
                        debug_print("Output matches expected output");
                    } else {
                        debug_print("Output does not match expected output");
                        // Wrong answer, change status
                        status_str = "wrong_answer";
                    }
                }
                break;
            case OJ_TL:
                debug_print("Input item %zu timed out", i);
                error_str = "Time limit exceeded";
                status_str = "time_limit_exceeded";
                break;
            case OJ_ML:
                debug_print("Input item %zu memory exceeded", i);
                error_str = "Memory limit exceeded";
                status_str = "memory_limit_exceeded";
                break;
            case OJ_RE:
                {
                    debug_print("Input item %zu runtime error", i);
                    
                    // Parse error output, extract error and stack trace
                    char *traceback_part = NULL;
                    char *error_part = NULL;
                    
                    // Try to extract standard Python error format
                    char *traceback_start = strstr(error_buffer, "Traceback");
                    if (traceback_start) {
                        // Copy full stack trace
                        traceback_part = strdup(traceback_start);
                        
                        // Find specific error information in stack trace
                        char *last_line = error_buffer + strlen(error_buffer);
                        
                        // Search backwards for last non-empty line
                        while (last_line > error_buffer && (*last_line == '\0' || *last_line == '\n' || *last_line == '\r')) {
                            last_line--;
                        }
                        
                        // Search backwards for line start
                        while (last_line > error_buffer && *last_line != '\n') {
                            last_line--;
                        }
                        if (*last_line == '\n') last_line++;
                        
                        if (last_line > error_buffer) {
                            error_part = strdup(last_line);
                        } else {
                            error_part = strdup(error_buffer);
                        }
                        
                        error_str = error_part ? std::string(error_part) : "";
                        traceback_str = traceback_part ? std::string(traceback_part) : "";
                        
                        free(traceback_part);
                        free(error_part);
                    } else {
                        // If there's no standard stack trace, use full error information
                        error_str = error_buffer ? std::string(error_buffer) : "";
                    }
                    
                    status_str = "runtime_error";
                }
                break;
            case OJ_CE:
                debug_print("Input item %zu compilation error", i);
                error_str = error_buffer ? std::string(error_buffer) : "";
                status_str = "compile_error";
                break;
            default:
                debug_print("Input item %zu unknown error", i);
                error_str = "Unknown error";
                status_str = "unknown_error";
        }
        
        errors.push_back(error_str);
        tracebacks.push_back(traceback_str);
        statuses.push_back(status_str);
        
        // If set to stop after the first error and current test failed, stop further tests
        if (stop_on_first_error && status_str != "success") {
            debug_print("Detected error, stopping further tests");
            i++; // Ensure current test result is included
            break;
        }
    }
    
    // Release pre-allocated buffers
    free(output_buffer);
    free(error_buffer);
    
    // Output entire JSON array
    output_json_array(input_list, outputs, expected_outputs, errors, tracebacks, statuses);
    
    // Release source code memory
    free(source_code);
    
    // Clean up compiled executable file
    if (is_compiled_language && strlen(executable_path) > 0) {
        debug_print("Cleaning up compiled executable file: %s", executable_path);
        if (unlink(executable_path) == -1) {
            debug_print("Failed to delete executable file: %s", strerror(errno));
        }
    }
    
    // Clean up shared source code file
    if (!is_compiled_language && strlen(shared_source_file) > 0) {
        debug_print("Cleaning up shared source code file: %s", shared_source_file);
        if (unlink(shared_source_file) == -1) {
            debug_print("Failed to delete shared source code file: %s", strerror(errno));
        } else {
            debug_print("Shared source code file cleanup successful");
        }
    }
    
    debug_print("Program finished");
    debug_print("Summary of security feature execution:");
    debug_print("- System call monitoring: %s", use_ptrace ? "enabled" : "disabled");
    debug_print("- Resource limits: Set");
    debug_print("- Privilege dropping: Executed");
    debug_print("- Network isolation: Set");
    
    // Clean up temporary files
    
    // Clean up sandbox directory (ensure user-created files are cleaned up)
    cleanup_sandbox_directory();
    
    return 0;
} 