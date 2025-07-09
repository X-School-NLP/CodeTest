import json

prompt = """Please generate Python code as an expert in constructing test data for ACM competition problems. The code should create input data for test cases that can trap brute-force algorithms. Follow these steps to ultimately provide me with 80 unit test inputs:**

1.  **Carefully Analyze the Provided AC Code:**
    - **Task:** Thoroughly read and understand the provided AC (Accepted) code, clarifying the algorithm it implements and its time complexity.
    - **Explanation:** Analyze the logic of this code, identify the correct solution approach, and estimate its time complexity. After understanding the performance of the optimal solution, infer which brute-force algorithms would likely time out with larger input sizes.

2.  **Identify the Problem Type:**
    - **Task:** What is the input type of this problem? (e.g., interval problem, tree problem, graph theory problem, number theory problem, string problem, etc.)
    - **Explanation:** Based on the problem description, clearly define the input data structure type.

3.  **Analyze Brute-Force Algorithms:**
    - **Task:** What brute-force algorithms can you conceive under this time constraint? Are these approaches feasible, but likely to exceed the time limit?
    - **Explanation:** Having understood the AC code and estimated the optimal solution's complexity, analyze possible implementations of brute-force algorithms and estimate their time complexity.

4.  **Data Construction Strategy:**
    - **Task:** What kind of data can trap the infeasible brute-force algorithms? Design such data.
    - **Explanation:** Based on the time complexity and characteristics of the brute-force algorithms, design a dataset that forces them to time out. Ensure the data pushes the brute-force algorithms to their limits, testing their performance with large datasets.

5.  **Generate Test Cases:**
    - **Task:** Generate 80 distinct test cases for this problem. The input data for each case must comply with the problem requirements, and some cases should push the upper/lower limits.
    - **Explanation:** When generating data, consider testing the performance of brute-force algorithms, ensuring these test cases are effective in causing brute-force solutions to time out or fail to complete within the time limit.

6.  **Problem Types and Data Construction Requirements:**
    - **Interval Problems:**
        - *Common Constructions: Generate small-length intervals (e.g., single-point intervals) and large-length intervals (e.g., the entire sequence).
    - **Prime Factorization Problems:**
        -* Maximize repeated prime factors: Generate powers of 2.
        -* Maximize distinct prime factors: Multiply the smallest primes.
        -* Maximize divisors: Refer to the OEIS sequence A002182.
    - **Tree Structure Problems:**
        -* Common Constructions: Chain, Star (Dandelion), Complete Binary Tree.
        -* Special Construction: Replace each node in a complete binary tree with a chain of length √n.
    - **Graph Theory Problems:**
        -* Common Constructions: Sparse graph, bipartite graph, Eulerian graph, DAG (Directed Acyclic Graph).
        -* Special Construction: Construct a tree first, then add a few edges to form the graph.
    - **String Processing Problems:**
        -* Common Constructions: All-`a' strings or strings with mostly `a's.
        -* Special Constructions: Palindrome strings, special characters, specific substrings, etc.

When conceptualizing code output, please think twice: what are the input and output format requirements for this problem?

- **If the problem's input requirements do not specify that the first line is the number of test cases, then use the following template for generate_test_inputs, ensuring its output aligns with this format. The final printed test_case_list should be a list where each element is a generated input:
    ##Format 1: {example1}

- **If the problem's input requirements specify that the first line is the number of test cases, then use the following template for generate_test_inputs, ensuring its output aligns with this format. The final printed test_case_list should be a list where each element is a generated input:
    ##Format 2: {example2}

Below are the [problem] and the [AC code]:

[Problem]: {problem}
[AC code]: {solution}
"""



example1 = """
```python
def generate_test_inputs(num_cases=100):
    # 参数生成器定义（示例）
    random.seed(42)  # 固定随机种子确保结果可复现
    param_generators = {{
        'n': [1, 1000] + [random.randint(2, 999) for _ in range(20)],
        'matrix': [gen_matrix(size) for size in (2, 5, 10)]
    }}
    
    # 正交组合引擎
    cases = []
    while len(cases) < num_cases:
        # 动态选择生成策略
        strategy = weighted_choice([
            ('boundary', 0.1), 
            ('random', 0.7),
            ('invalid', 0.2)
        ])
        
        # 执行策略对应的生成逻辑
        if strategy == 'boundary':
            case = (choice(param_generators['n']), 
                generate_boundary_array())
        elif ...:
            ...

        # 约束校验
        if is_valid_case(case):
            cases.append(case)
    return cases[:num_cases]
def main():
    # Generate test cases
    test_cases = generate_test_inputs()
    test_case_list = []
    # Print or process the test cases as needed
    for case in test_cases:
        test_case_list.append(case)
    print(test_case_list)

if __name__ == "__main__":
    main()
```
"""

example2 = """
```python
import random
def generate_single_testcase():
    strategies = ['all_ones', 'all_zeros', 'half', 'no_valid', 'random_yes', 'random_no']
    strategy = random.choice(strategies)
    
    # 生成L的值
    if random.random() < 0.05:   #接近边界的概率需要设置较低的值
        L = random.randint(90000, 100000)
    else:
        L = random.choice([1, 2, 3, 4, 5, 10, 100, 1000, 5000, 10000])

    # 生成S的逻辑
    if strategy == 'all_ones':
        S = '1' * L
    elif strategy == 'all_zeros':
        S = '0' * L
    elif strategy == 'half':
        m = (L + 1) // 2
        S = '1' * m + '0' * (L - m)
    elif strategy == 'no_valid':
        s = []
        current_ones = 0
        for i in range(1, L + 1):
            max_allowed = (i - 1) // 2
            if current_ones + 1 <= max_allowed:
                s.append('1')
                current_ones += 1
            else:
                s.append('0')
        S = ''.join(s)
    elif strategy == 'random_yes':
        k = random.randint(1, L)
        required = (k + 1) // 2
        prefix = ['1'] * required + ['0'] * (k - required)
        random.shuffle(prefix)
        suffix = [random.choice(['0', '1']) for _ in range(L - k)]
        S = ''.join(prefix + suffix)
    elif strategy == 'random_no':
        s = []
        current_ones = 0
        for i in range(1, L + 1):
            max_allowed = (i - 1) // 2
            if current_ones + 1 <= max_allowed:
                s.append('1')
                current_ones += 1
            else:
                s.append('0')
        S = ''.join(s)
    else:
        S = ''.join(random.choices(['0', '1'], k=L))
    return (L, S)
def generate_test_inputs(num_cases=100):
    random.seed(42)
    test_case_list = []
    
    for _ in range(num_cases):
        # 生成完整的测试输入字符串
        T = random.randint(1, 10)  # 每个测试输入包含1~10个测试用例
        sum_L = 0
        test_input = []
        for _ in range(T):
            remaining = 10**6 - sum_L
            if remaining <= 0:
                break
            # 动态调整L的生成范围
            max_possible_L = min(100000, remaining)
            L = random.randint(1, max_possible_L) if remaining > 100000 else remaining
            
            # 生成单个测试用例
            _, S = generate_single_testcase()
            L = min(L, 100000)  # 确保L不超过题目限制
            test_input.append(f"{{L}}\n{{S}}")
            sum_L += L
        # 构造完整的输入字符串
        T_actual = len(test_input)
        full_input = f"{{T_actual}}\n" + "\n".join(test_input)
        test_case_list.append(full_input)
    return test_case_list[:num_cases]
def main():
    test_cases = generate_test_inputs()
    print(test_cases)
if __name__ == "__main__":
    main()
```
"""

path = ''
path_save = ''


with open(path, 'r') as file, open(path_save, 'w') as save_file:
    data = [json.loads(line.strip()) for line in file]
    for i,dic in enumerate(data):

        solution = dic['solutions'][0]
        question = prompt.format_map({"problem": dic['question'], "solution": solution, "example1": example1, "example2": example2})

        new_dic = {"custom_id": f"{dic['custom_id']}", "body": {"messages": [{"role": "user", "content": question}], "max_tokens": 8192, "temperature": 0.7}}
        save_file.write(json.dumps(new_dic, ensure_ascii=False)+'\n')
