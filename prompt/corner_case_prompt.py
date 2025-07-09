import json

prompt = """You are an expert in constructing boundary test cases for ACM competition problems. Please generate Python code to create strictly boundary-conditioned test case input data that precisely exposes the performance flaws of brute-force algorithms in extreme scenarios. Follow these steps to generate 20 strictly boundary unit test inputs:

1. **Carefully Analyze the Provided AC Code:**  
   - **Question:** Clarify the problem solved by the AC code, its core algorithm, and time complexity (e.g., O($n\log n$), O($\sqrt{{n}}$)).  
   - **Explanation:** Precisely identify optimization points in the correct solution (e.g., preprocessing, divide-and-conquer, dynamic programming) to deduce which boundary inputs would cause a brute-force algorithm (e.g., O($n^2$) enumeration, recursive backtracking) to time out due to computational overload.  

2. **Problem Type and Boundary Definition:**  
   - **Question:** What is the input type (interval/tree/graph/number theory/string)? What are the core boundary conditions for this type?  
   - **Explanation:** Boundaries vary by problem type (examples):  
        - *Interval problems*: $n$=1 (single point), $n$=upper limit (full sequence), left=right (zero-length interval).  
        - *Number theory*: Large primes (e.g., 1e9+7), $2^{{30}}$ (largest 32-bit power of 2), all-1 arrays (factorization degradation).  
        - *Tree structures*: Chains (longest path), star graphs (maximum degree at center), empty trees ($n$=0).  
        - *Strings*: All 'a' (maximal repeated substring), all distinct characters (no repeats), length=upper limit (e.g., $1e5$).  

3. **Brute-Force Algorithm Boundary Vulnerability Analysis:**  
   - **Question:** Under which boundary inputs does the brute-force algorithm trigger its worst-case time complexity?  
   - **Explanation:** After understanding the AC code and estimating its complexity, analyze possible brute-force implementations (e.g., exhaustive search, nested loops, recursion) and their performance at maximum input sizes. Examples:  
        - *Interval problems*: At $n=1e4$, O($n^2$) enumeration requires ~5e8 operations (exceeding 1e8 operations/second limits).  
        - *Number theory*: For $2^{{30}}$ (~1e9), trial division checks up to $\sqrt{{2^{{30}}}}\approx$3e4 times, but for large primes (e.g., 1e9+7), checks reach ~3e4+1 times (10k$\times$ slower than composites).  
        - *Tree structures*: Chain structures cause brute-force DFS recursion depth to reach n (e.g., $n$=1e4 → stack overflow/timeout).  

4. **Boundary Data Construction Strategy:**  
   - **Question:** How to construct inputs that precisely trigger the worst-case scenario for brute-force algorithms?  
   - **Explanation:** Design boundary data based on problem type and brute-force weaknesses:  
        - *Input size boundaries*: $n$=1 (minimum), n=upper limit (e.g., 1e4).  
        - *Extreme structures*: Fully overlapping/non-overlapping intervals, chain/star trees, all-identical/all-distinct strings.  
        - *Value extremes*: Maximum/minimum values (e.g., 1e9, -1e9), special numbers (primes, powers of 2, factorials).  
        - *Combined boundaries*: Multiple boundary conditions stacked (e.g., $n$=1e4 with all single-point intervals).  

5. **Boundary Test Case Generation Rules:**  
   - **Question:** How to ensure all 20 test cases are 100\%% boundary scenarios?  
   - **Explanation:** Prioritize these strategies to guarantee brute-force timeouts:  
        - *Input size boundaries* ($n$=1, $n$=upper limit).  
        - *Extreme structures* (chain trees, fully overlapping intervals, all-`a' strings).  
        - *Value extremes* (large primes, $2^{{30}}$).  
        - *Combined boundaries* (n=upper limit + extreme structure).  
        - *Each test case must explicitly label its boundary type* (e.g., ``$n$=upper limit + chain tree'').



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
