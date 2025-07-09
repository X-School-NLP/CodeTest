import json

spj_prompt = """
You are a builder of an ACM programming contest evaluation system. Your task is to determine whether a custom checker is needed based on problem information, and output a complete Python script for evaluation when necessary. 
    

    ------ 

    【Task Objectives】
1. Determine whether a custom checker is needed:
  - If there are multiple valid outputs (construction problems, multiple solutions, order-independent, etc.);
  - Or output contains floating-point numbers with allowed precision errors;
  - Or output format is not unique (such as ignoring spaces, line order, etc.);
  - Or output correctness cannot be determined through simple string comparison;
  - Then this problem requires a custom checker.

2. If needed, generate a complete Python script (named checker):
  - Script uses sys.argv to receive three command-line arguments: input_str, output_str, reference_output_str
  - Judging logic is written in the is_valid_output() function, returning a boolean value;
  - Script includes main() entry point, ultimately outputting with print(True) or print(False);
  - You must output the complete Python framework below and only complete the judging logic in is_valid_output:


```python
import sys
def is_valid_output(input_str, output_str, reference_output_str):
    # Please complete the judging logic here
    ...

def main():
    if len(sys.argv) != 4:
        print(False)
        return
    input_str = sys.argv[1]
    output_str = sys.argv[2]
    reference_output_str = sys.argv[3]
    print(is_valid_output(input_str, output_str, reference_output_str))
if __name__ == "__main__":
    main()
```

    ------

[Problem Information]
Problem Description: {description}  
Input Format: {input_format}  
Output Format: {output_format}  
Input/Output Examples: {examples}

 ------

Please output your answer in the following format:
```
Whether custom checker is needed: Yes/No

Reason: ...

If needed, please output the complete Python script:
<Complete script code (must include framework)>
```
"""


path = ''
path_save = ''

with open(path1, 'r') as file1, open(path_save, 'w') as save_file:

    data1 = [json.loads(line.strip()) for line in file1]
    print(len(data1))
    for i,dic in enumerate(data1):
        question = spj_prompt.format_map({'description': dic['description'], 'input_format': dic['input_format'], 'output_format': dic['output_format'], 'examples': dic['examples']})


        new_dic = {"custom_id": f"{dic['custom_id']}", "body": {"messages": [{"role": "user", "content": question}], "max_tokens": 8192, "temperature": 0.7}}
        save_file.write(json.dumps(new_dic, ensure_ascii=False)+'\n')
