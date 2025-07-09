import json

spj_prompt = """
You are a reviewer of a programming contest evaluation system. Your task is to verify the correctness of a custom checker code and provide corrected complete code when issues exist. 

    ------

    【Task Objectives】
1. Check if the Checker has problems:
  - Can it correctly handle input formats and boundary conditions;
  - Does it strictly follow the problem requirements to determine correctness;
  - Is it robust, returning False when dealing with illegal output or exceptional input;
  - Does it use print(True) / print(False) as output format.
  
2. If problems exist, please correct the code:
  - Keep using sys.argv to receive input_str, output_str, reference_output_str;
  - Judging logic should be in the is_valid_output() function;
  - Maintain complete code structure and be directly executable.

------ 

[Problem Information]
Problem Description: {description} 
Input Format: {input_format}  
Output Format: {output_format}  
Examples: {examples} 

------ 

[Current Checker Script]
```python
{checker_code}
```

Please output:
```
Does the Checker have problems: Yes / No
Reason: ...
If problems exist, please output the corrected complete Python script:
<Corrected code>
```
"""


path = ''
path_save = ''

with open(path, 'r') as file1, open(path_save, 'w') as save_file:
    custom_id = []
    for i,line in enumerate(file1):
        dic = json.loads(line.strip())
        question = spj_prompt.format_map({'description': dic['description'], 
                                        'input_format': dic['input_format'], 
                                        'output_format': dic['output_format'], 
                                        'examples': dic['examples'], 
                                        'checker': dic['checker']
                                        })

        new_dic = {"custom_id": f"{dic['custom_id']}", "body": {"messages": [{"role": "user", "content": question}], "max_tokens": 8192, "temperature": 0.7}}
        save_file.write(json.dumps(new_dic, ensure_ascii=False)+'\n')