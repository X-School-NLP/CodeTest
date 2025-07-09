# Judge Sandbox System Documentation

## Overview

The Judge Sandbox System is a secure code execution environment for offline problem evaluation. It supports multiple programming languages (Python, C++, C) and provides comprehensive security isolation mechanisms, including file system isolation, process monitoring, and resource limitations.

## System Features

- **Multi-language Support**: Automatic detection and support for Python, C++, and C languages
- **Secure Sandbox**: File system isolation, process monitoring, privilege downgrade
- **Resource Control**: Time limits, memory limits, system call monitoring
- **Multiple Execution Modes**: Support for no-input execution, standard answer generation, and complete judging
- **JSON Output**: Structured output for programmatic processing

## Three Execution Modes

### 1. No-Input Direct Execution Mode (Test Case Generator Mode)

**Purpose**: Used to execute programs that generate test cases without requiring external input

**Usage**:
```bash
./judge <source_code_file_path> [time_limit] [memory_limit] [security_options]
```

**Examples**:
```bash
# Execute generator program with 5-second time limit and 512MB memory limit
./judge generator.py 5.0 512

# Enable debug mode
./judge generator.cpp 10.0 1024 --debug
```

**Features**:
- Program receives no standard input
- Directly executes program and retrieves output
- Suitable for data generators, special output programs, etc.

### 2. Input Without Expected Output Mode (Solution Mode)

**Purpose**: Run standard answer programs to generate correct output, typically used to generate expected output for test cases

**Usage**:
```bash
./judge <source_code_file_path> [time_limit] [memory_limit] <input_file_path> [stop_on_first_error] [security_options]
```

**Input File Format**:
```json
{
  "inputs": ["input1", "input2", "input3"],
  "outputs": []
}
```
Or simplified format:
```json
["input1", "input2", "input3"]
```

**Examples**:
```bash
# Run standard answer to generate expected output
./judge solution.cpp 2.0 256 inputs.json 0

# Use Python standard answer
./judge standard_solution.py 5.0 512 test_inputs.json 0 --debug
```

**Features**:
- Program reads from standard input
- Returns actual output for each test case
- No output comparison performed
- Status field is "success" (if program runs normally)

### 3. Input With Expected Output Mode (Judge Mode)

**Purpose**: Complete judging mode that compares user program output with expected output

**Usage**:
```bash
./judge <source_code_file_path> [time_limit] [memory_limit] <input_file_path> [stop_on_first_error] [security_options]
```

**Input File Format**:
```json
{
  "inputs": ["input1", "input2", "input3"],
  "outputs": ["expected_output1", "expected_output2", "expected_output3"]
}
```

**Examples**:
```bash
# Complete judging mode
./judge user_solution.py 2.0 256 test_cases.json 1

# Run all test cases (don't stop on first error)
./judge user_code.cpp 5.0 1024 all_tests.json 0 --ptrace
```

**Features**:
- Program reads from standard input
- Compares output with expected output
- Returns detailed judging results
- Status field includes "success", "wrong_answer", "time_limit_exceeded", etc.

## Parameter Details

### Required Parameters

1. **Source Code File Path**: The source code file to execute
   - Supports relative and absolute paths
   - Language auto-detection based on file extension and content

### Optional Parameters

2. **Time Limit** (default: 5.0 seconds)
   - Float number in seconds
   - Returns "time_limit_exceeded" when exceeded

3. **Memory Limit** (default: 1024 MB)
   - Integer in MB
   - Returns "memory_limit_exceeded" when exceeded

4. **Input List File Path** (optional)
   - No-input mode if not provided
   - Supports JSON format and simple list format

5. **Stop on First Error** (default: 0)
   - 0: Run all test cases
   - 1: Stop after first error

6. **Security Options** (optional)
   - `--debug`: Enable debug mode with detailed logging
   - `--ptrace`: Enable ptrace system call monitoring

## Input Format Specification

### JSON Complete Format
```json
{
  "inputs": [
    "First test case input",
    "Second test case input",
    "Input with newlines\nmulti-line content"
  ],
  "outputs": [
    "First test case expected output", 
    "Second test case expected output",
    "Third test case expected output"
  ]
}
```

### JSON Simplified Format (Input Only)
```json
["input1", "input2", "input3"]
```

### Special Character Handling
- Newlines: Use `\n`
- Quotes: Use `\"` escape
- Backslashes: Use `\\` escape

## Output Format

The system always returns JSON array format, with each element corresponding to a test case:

```json
[
  {
    "input": "Test case input",
    "output": "Program actual output",
    "expected_output": "Expected output (if provided)",
    "result": null,
    "error": "Error message (if any)",
    "traceback": "Stack trace (Python runtime errors)",
    "status": "Execution status"
  }
]
```

### Status Code Descriptions

- **success**: Program executed normally
- **wrong_answer**: Output doesn't match expected
- **time_limit_exceeded**: Timeout
- **memory_limit_exceeded**: Memory limit exceeded
- **runtime_error**: Runtime error
- **compile_error**: Compilation error (C++/C)
- **format_error**: Input format error
- **unknown_error**: Unknown error

## Supported Programming Languages

### Python
- **Detection Features**: `import`, `def`, `print()`, file extension `.py`
- **Execution Method**: Direct interpretation
- **Error Handling**: Captures complete traceback information

### C++
- **Detection Features**: `#include <iostream>`, `std::`, `cout`, `cin`, file extensions `.cpp/.cc`
- **Compilation Options**: `g++ -O2 -std=c++17`
- **Execution Method**: Compile then execute

### C
- **Detection Features**: `#include <stdio.h>`, `printf`, `scanf`, file extension `.c`
- **Compilation Options**: `g++ -O2` (C syntax compatible)
- **Execution Method**: Compile then execute

## Security Mechanisms

### File System Isolation
- Create temporary sandbox directory
- Limit file access permissions
- Automatic cleanup of temporary files

### Process Monitoring
- Use ptrace to monitor system calls
- Restrict dangerous system calls
- Prevent privilege escalation

### Resource Limitations
- CPU time limits
- Memory usage limits
- File descriptor limits
- Process count limits

### Permission Control
- Downgrade to low-privilege user
- Disable network access
- Restrict file creation permissions

## Usage Examples

### Example 1: Test Case Generator
```bash
# Run data generator
./judge data_generator.py 10.0 512

# Output example
[
  {
    "input": "",
    "output": "5\n1 2 3 4 5\n",
    "expected_output": null,
    "result": null,
    "error": "",
    "traceback": "",
    "status": "success"
  }
]
```

### Example 2: Generate Standard Answer
```bash
# Prepare input file inputs.json
{
  "inputs": ["5\n1 2 3 4 5", "3\n-1 0 1"],
  "outputs": []
}

# Run standard answer program
./judge standard_solution.cpp 5.0 256 inputs.json 0

# Output example
[
  {
    "input": "5\n1 2 3 4 5",
    "output": "15\n",
    "expected_output": "",
    "result": null,
    "error": "",
    "traceback": "",
    "status": "success"
  },
  {
    "input": "3\n-1 0 1", 
    "output": "0\n",
    "expected_output": "",
    "result": null,
    "error": "",
    "traceback": "",
    "status": "success"
  }
]
```

### Example 3: Complete Judging
```bash
# Prepare test file test_cases.json
{
  "inputs": ["5\n1 2 3 4 5", "3\n-1 0 1"],
  "outputs": ["15\n", "0\n"]
}

# Judge user code
./judge user_solution.py 2.0 256 test_cases.json 1

# Output example (correct)
[
  {
    "input": "5\n1 2 3 4 5",
    "output": "15\n",
    "expected_output": "15\n", 
    "result": null,
    "error": "",
    "traceback": "",
    "status": "success"
  }
]

# Output example (incorrect)
[
  {
    "input": "5\n1 2 3 4 5",
    "output": "14\n", 
    "expected_output": "15\n",
    "result": null,
    "error": "",
    "traceback": "",
    "status": "wrong_answer"
  }
]
```

## Error Handling

### Compilation Error Example
```json
[
  {
    "input": "5\n1 2 3 4 5",
    "output": "",
    "expected_output": "15\n",
    "result": null,
    "error": "test.cpp:5:5: error: 'cout' was not declared in this scope",
    "traceback": "",
    "status": "compile_error"
  }
]
```

### Runtime Error Example
```json
[
  {
    "input": "0",
    "output": "",
    "expected_output": "inf",
    "result": null,
    "error": "ZeroDivisionError: division by zero",
    "traceback": "Traceback (most recent call last):\n  File \"test.py\", line 3, in <module>\n    print(1/int(input()))\nZeroDivisionError: division by zero",
    "status": "runtime_error"
  }
]
```

## Performance Optimization

- **Compilation Caching**: C++/C code compiled once, reused for multiple test cases
- **Memory Reuse**: Pre-allocated buffers avoid repeated memory allocation
- **Process Monitoring**: Efficient ptrace monitoring mechanism
- **File System**: Create temporary files in sandbox to reduce I/O overhead

## Important Notes

1. **Permission Requirements**: Recommended to run with root privileges for full security mechanisms
2. **Resource Cleanup**: System automatically cleans up temporary files and processes
3. **Concurrency Safety**: Each execution uses independent sandbox directory
4. **Output Comparison**: Automatically handles format differences like trailing spaces, empty lines
5. **Debug Mode**: Use `--debug` parameter for detailed execution logs

## Troubleshooting

### Common Issues

1. **"Cannot create sandbox directory"**
   - Check `/tmp` directory permissions
   - Ensure sufficient disk space

2. **"Compilation failed"**
   - Check if g++ compiler is installed
   - Verify source code syntax correctness

3. **"Insufficient permissions"**
   - Run with sudo or check user permissions
   - Ensure system supports required security mechanisms

### Debugging Methods

```bash
# Enable detailed debug output
./judge test.py 5.0 256 inputs.json 0 --debug

# Enable system call monitoring
./judge test.cpp 5.0 512 inputs.json 0 --ptrace --debug
```

## System Requirements

- **Operating System**: Linux (Ubuntu 18.04+ recommended)
- **Compiler**: g++ (C++17 support)
- **Python**: Python 3.x
- **Permissions**: Root privileges recommended for full security mechanisms
- **Dependencies**: ptrace, unshare, mount and other system call support 