# Klear-CodeTest: Scalable Test Case Generation and Stable Sandbox System for Code Reinforcement Learning



Welcome to **Klear-CodeTest**, the official repository for our scalable and reliable test case generation framework tailored for **code reinforcement learning (RL)**. This project provides:

- A **Generator-Validation (G-V) framework** to synthesize diverse, high-quality test cases.
- A **multi-layered security sandbox system (Judge)** for stable and efficient execution.
- A curated dataset of **27,965 competitive programming problems**, each equipped with validated test cases.


🔗 **Project Website**: https://github.com/Kwai-Klear/CodeTest
🔗 **dataset**: https://huggingface.co/datasets/Jianlp/Klear-CodeTest

---

## 🔧 Features

- 🧪 **Generator-Validation Framework** with iterative feedback to refine LLM-generated test inputs.
- 🧰 **Corner and Regular Test Case Generator Prompts** tailored for programming problem boundaries and brute-force traps.
- ✅ **Consistency Validation** mechanism using multiple gold solutions to ensure input correctness.
- 🔒 **Judge Sandbox**: Secure, resource-limited, and faster than Firejail for large-scale evaluation.
- 🧠 **Checker Program Generation & Repair**: Automated pipeline to construct and validate special judges for multi-solution or floating-point tasks.

---

## 🧬 Test Case Generation Pipeline (Code Structure)


<p align="center">
  <img src="images/GV-framework.png" alt="GV Framework" width="700"/>
</p>

### Overview

Klear-CodeTest provides two main pipeline components for scalable test case generation:

1. **Standard Test Case Generation Pipeline** (`pipeline/gen.py`)
2. **Special Judge Test Case Generation Pipeline** (`pipeline/special_judge_gen.py`)

Both pipelines implement the Generator-Validation (G-V) framework to ensure high-quality test case synthesis.

---

### 🚀 Quick Start

#### Prerequisites

```bash
# Build the sandbox system
cd sandbox/
make

# Install Python dependencies
pip install tqdm
```

#### Standard Test Case Generation

```bash
cd pipeline/

# Use sample data from data directory
python gen.py --input ../data/sample.jsonl --output ../data/sample_with_generated_testcases.jsonl

# Advanced usage with custom parameters
python gen.py \
    --input ../data/sample.jsonl \
    --output ../data/sample_with_generated_testcases.jsonl \
    --gen_index 0 \
    --workers 16
```

#### Special Judge Test Case Generation

```bash
cd pipeline/

# Use special judge pipeline for problems requiring custom validation
python special_judge_gen.py \
    --input ../data/spj_sample.jsonl \
    --output ../data/spj_sample_with_special_testcases.jsonl \
    --gen_index 0 \
    --workers 16
```

---

### 📋 Pipeline Details

#### 1. Standard Pipeline (`gen.py`)

**Purpose**: Generate test cases for problems with unique correct outputs.

**Three-Step Process**:
1. **Input Generation**: Execute input generator code to produce diverse test inputs
2. **Output Generation**: Use the first gold solution to generate corresponding outputs  
3. **Consistency Validation**: Verify output consistency using the last gold solution

**Command Line Arguments**:
- `--input`: (Required) Path to input JSONL file containing problems, solutions, and input generators
- `--output`: (Required) Path to output JSONL file where generated test cases will be saved
- `--gen_index`: (Optional) Index of which input generator to use from the input_generator array (default: 0, meaning first generator)
- `--workers`: (Optional) Number of parallel worker threads for concurrent processing (default: 8)

#### 2. Special Judge Pipeline (`special_judge_gen.py`)

**Purpose**: Generate test cases for problems requiring custom validation logic.

**Enhanced Process**:
1. **Input Generation**: Same as standard pipeline
2. **Output Generation**: Same as standard pipeline  
3. **Special Judge Validation**: Use provided checker function to validate outputs instead of simple equality comparison

**Command Line Arguments**:
- `--input`: (Required) Path to input JSONL file containing problems, solutions, input generators, and checker functions
- `--output`: (Required) Path to output JSONL file where generated test cases will be saved
- `--gen_index`: (Optional) Index of which input generator to use from the input_generator array (default: 0, meaning first generator)
- `--workers`: (Optional) Number of parallel worker threads for concurrent processing (default: 8)

**Key Difference**: Integrates custom checker functions to handle:
- Multiple valid solutions
- Floating-point comparisons with tolerance
- Complex output validation logic

---

### 📄 Input Data Format

#### Standard Pipeline Input

```json
{
    "custom_id": "problem_001",
    "question": "Problem description",
    "solutions": ["solution_code_1", "solution_code_2"],
    "input_generator": ["generator_code_1", "generator_code_2"],
    "type": "stdin",
    "input_output": "public_unit_tests",
    "time-limit": 30,
    "memory-limit": 1024
}
```

#### Special Judge Pipeline Input

```json
{
    "custom_id": "problem_002",
    "question": "Problem description", 
    "solutions": ["solution_code_1", "solution_code_2"],
    "input_generator": ["generator_code_1", "generator_code_2"],
    "checker": ["checker_code_1", "checker_code_2"],
    "type": "stdin",
    "input_output": "public_unit_tests",
    "time-limit": 30,
    "memory-limit": 1024
}
```

### 📤 Output Data Format

#### Standard Pipeline Output

```json
{
    "custom_id": "problem_001",
    "question": "Problem description",
    "solutions": ["solution_code_1", "solution_code_2"],
    "input_generator": ["generator_code_1", "generator_code_2"],
    "type": "stdin",
    "error_info": null,
    "reward": {
        "ground_truth": {
            "input_output": [
                {"input": "1 2\n", "output": "3\n"},
                {"input": "5 7\n", "output": "12\n"}
            ],
            "type": "stdin",
            "fn_name": null
        }
    },
    "time-limit": 30,
    "memory-limit": 1024
}
```

#### Special Judge Pipeline Output

```json
{
    "custom_id": "problem_002",
    "question": "Problem description",
    "solutions": ["solution_code_1", "solution_code_2"],
    "input_generator": ["generator_code_1", "generator_code_2"],
    "checker": ["checker_code_1", "checker_code_2"],
    "type": "stdin",
    "error_info": null,
    "reward": {
        "ground_truth": {
            "input_output": [
                {"input": "1 2\n", "output": "3\n"},
                {"input": "5 7\n", "output": "12\n"}
            ],
            "type": "stdin",
            "fn_name": null
        }
    },
    "time-limit": 30,
    "memory-limit": 1024
}
```

**Note**: The `checker` field only appears in the special judge pipeline output. Standard pipeline output does not include this field.

---

### ⚙️ Configuration

#### Key Parameters (configurable in pipeline scripts)

```python
TL_GEN, TL_RUN = 30.0, 5.0          # Time limits: generator 30s, runtime 5s
ML_GEN, ML_RUN = 10240, 1024        # Memory limits: generator 10GB, runtime 1GB  
MAX_PARALLEL_JUDGE = 64             # Maximum parallel sandbox processes
```

#### Advanced Features

**Resume Capability**: Both pipelines support resuming interrupted runs
- Automatically skip already processed `custom_id`s based on existing output file
- Safe to run multiple times until completion
- Real-time result saving prevents data loss on interruption

**Parallel Processing**: Configurable multi-threading
- Default: 8 worker threads
- Adjustable based on system resources via `--workers` parameter
- Automatic resource limit enforcement per process

**Error Handling**: Comprehensive error management
- Detailed error reporting in `error_info` field for failed cases
- Graceful degradation on individual task failures
- Statistics tracking and real-time progress monitoring

---

## 📊 Dataset

- 27,965 competition-level problems
- Average of 86 validated test cases per problem

---

## 🧪 Benchmarking & Results


### 🔍 Explanation

We evaluate the correctness and discriminative power of CodeTest test cases across different programming languages, comparing with both public and gold test cases from CodeContests.

- **TPR** (True Positive Rate): Measures whether test cases accept correct solutions.

- **TNR** (True Negative Rate): Measures whether test cases reject incorrect solutions.

The following table presents test case quality evaluation across different programming languages.  
**“P”** and **“G”** represent the **public** and **generated** test cases used in **CodeContests**, respectively.

| Dataset | Language | TPR ↑ | TNR ↑ |
|---------|----------|--------|--------|
| **CodeContests (P)** | C/C++ | 45.8 | 53.8 |
|  | Python3 | 77.6 | 45.4 |
|  | Python2 | 68.8 | 38.1 |
|  | **All** | 71.9 | 47.2 |
| **CodeContests (G)** | C/C++ | 86.0 | 92.8 |
|  | Python3 | 91.3 | 82.7 |
|  | Python2 | 84.1 | 74.6 |
|  | **All** | 89.1 | 84.3 |
| **CodeTest (Ours)** | C/C++ | **86.6** | **93.6** |
|  | Python3 | **93.4** | **87.5** |
|  | Python2 | **85.8** | **78.6** |
|  | **All** | **91.4** | **87.8** |



---


## Acknowledgments

## Citation
If you find this project is useful in your own work, please consider citing as follows:
```
@misc{klear_codetest,
    title = {Klear-CodeTest: Scalable Test Case Generation and Stable Sandbox System for Code Reinforcement Learning},
    url = {https://github.com/Kwai-Klear/CodeTest},
    author = {{Klear Team, Kuaishou Technology}},
    month = {July},
    year = {2025}
}
```

