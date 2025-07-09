#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess, json, argparse, concurrent.futures, threading, os, tempfile, re, ast, time
from tempfile import TemporaryDirectory
from tqdm import tqdm
from datetime import datetime
from contextlib import contextmanager
import uuid, pathlib
import multiprocessing

# ────────────── Configuration Section ──────────────
TL_GEN, TL_RUN = 30.0, 5.0  # Time limits: generator 30s, runtime 5s
ML_GEN, ML_RUN = 10240, 1024  # Memory limits: generator 10GB, runtime 1GB
MAX_PARALLEL_JUDGE = 64  # Maximum parallel judge processes

# ────────────── Global Thread Locks & Counters ──────────────
non_empty_count = 0  # Changed to int
non_empty_lock = threading.Lock()
judge = "../sandbox/judge"
stop = "0"
judge_sema = threading.Semaphore(MAX_PARALLEL_JUDGE)  # Limit concurrent judge processes

log_lock = threading.Lock()
def log(msg):
    with log_lock:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

# ────────────── Code Wrapping ──────────────

from collections import Counter
stats_counter = Counter()
stats_lock = threading.Lock()

def inc_stats(key):
    """Atomically increment statistics counter"""
    with stats_lock:
        stats_counter[key] += 1

# ────────────── Real-time Statistics Thread ──────────────
def print_stats(idx):
    with stats_lock:
        msg = ", ".join(f"{k}: {v}" for k, v in stats_counter.items())
    print(f"[Real-time Stats] Line {idx} processed, stats: {msg}", flush=True)

# ────────────── Restricted Judge Execution Function ──────────────
def run_judge(cmd, timeout_sec):
    """Use Semaphore to limit concurrency, add timeout and stderr capture"""
    # Check if executable exists
    if not os.path.exists(cmd[0]):
        error_msg = f"Executable not found: {cmd[0]}"
        return None, error_msg
    
    with judge_sema:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            return result
        except subprocess.TimeoutExpired as e:
            error_msg = f"Judge timeout: {e}"
            return None, error_msg
        except Exception as e:
            error_msg = f"Judge execution error: {e}"
            return None, error_msg

# ────────────── Temporary File Utility Functions ──────────────
@contextmanager
def with_tmp_code(code: str):
    """Context manager for creating temporary Python code files"""
    with TemporaryDirectory() as td:
        p = pathlib.Path(td) / f"{uuid.uuid4().hex}.py"
        p.write_text(code, encoding='utf-8')
        yield str(p)

@contextmanager
def with_tmp_io_file(io_str: str):
    """Context manager for creating temporary IO files"""
    with TemporaryDirectory() as td:
        p = pathlib.Path(td) / f"{uuid.uuid4().hex}.txt"
        p.write_text(io_str, encoding='utf-8')
        yield str(p)

# ────────────── Main Processing Functions ──────────────
def generate_input(idx, code):
    with with_tmp_code(code) as src_path:
        log(f"[line {idx}] Executing input generation")
        cmd = [judge, src_path, str(TL_GEN), str(ML_GEN)]
        
        result = run_judge(cmd, (TL_GEN + 5) * 100)  # Give judge process ample timeout
        
        if isinstance(result, tuple):  # Timeout case
            return [], result[1]
        
        res = result
        log(f"[line {idx}] Input generation completed")
        
        if res.stderr:
            log(f"[line {idx}] Input stderr: {res.stderr.strip()}")

        try:
            res_data = json.loads(res.stdout)

            if not isinstance(res_data[0]['output'], str):
                return [], f"Generator run failed, details: 'traceback': {res_data[0]['traceback']}, 'status': {res_data[0]['status']}"
            info = res_data[0]['output']
            info = ast.literal_eval(info.strip())
            error = None
            if not isinstance(info, list):
                error = f"Generator output cannot be parsed as a list"
                info = []
            return info, error
        except json.JSONDecodeError:
            return [], "Sandbox returned format cannot be parsed as JSON"
        except (ValueError, SyntaxError): 
            return [], f"Generator output cannot be parsed as a list, generator execution details: {res_data}"

def generate_output(idx, input_list, solution, typ, fn_name):
    solution = solution.replace("freopen", "//freopen")
    init_code = solution

    io_str = {"input": input_list, "output": []}
    io_str = str(io_str)

    with with_tmp_code(solution) as src_path, \
         with_tmp_io_file(io_str) as io_path:
        
        log(f"[line {idx}] Executing output generation")
        cmd = [judge, src_path, str(TL_RUN), str(ML_RUN), io_path, stop]
        result = run_judge(cmd, (TL_RUN + 5) * 100)  # Give judge process ample timeout
        
        if isinstance(result, tuple):  # Timeout case
            return [], result[1]
        
        res = result
        log(f"[line {idx}] Output generation completed")
        
        if res.stderr:
            log(f"[line {idx}] Output stderr: {res.stderr.strip()}")

        try:
            info = json.loads(res.stdout)
            filtered = [
                {"input": item["input"], "output": item["output"]}
                for item in info
                if (
                    item.get("status") == "success"                # 1) status is success
                    and item.get("output") is not None             # 2) output is not null
                )
            ]

            error_info = None
            if not filtered:
                error_info = f"Input generator produced inputs that cannot pass correct code submissions,\nCode:\n{init_code},\n Detailed error info:\n{info[0]} "
            return filtered, error_info
        except json.JSONDecodeError:
            return [], "Sandbox returned format cannot be parsed as JSON"

# ────────────── Execute Judge ──────────────
def get_good_output(idx, unit_dic, solution0, solution, typ, fn_name):
    solution = solution.replace("freopen", "//freopen")
    solution1 = solution
    input_list, output_list = [], []
    for unit in unit_dic:
        input_list.append(unit["input"])
        output_list.append(unit["output"])

    io_str = {"input": input_list, "output": output_list}
    io_str = str(io_str)

    with with_tmp_code(solution) as src_path, \
         with_tmp_io_file(io_str) as io_path:
        log(f"[line {idx}] Executing judge")
        cmd = [judge, src_path, str(TL_RUN), str(ML_RUN), io_path, stop]
        result = run_judge(cmd, (TL_RUN + 5) * 100)  # Give judge process ample timeout
        
        if isinstance(result, tuple):  # Timeout case
            return [], result[1]
        
        res = result
        log(f"[line {idx}] Judge execution completed")
        
        if res.stderr:
            log(f"[line {idx}] Judge stderr: {res.stderr.strip()}")
        
        try:
            
            info = json.loads(res.stdout)
            filtered = [
                {"input": item["input"], "output": item["output"]}
                for item in info
                if (
                    item.get("status") == "success"                # 1) status is success
                    and item.get("output") is not None             # 2) output is not null
                )
            ]

            error_info = None
            if not filtered:
                error_info = f"Generator code produced inputs that cannot make two correct submissions generate same output, correct code1 successfully generated 'expected_output', code2 generated 'output',\n Detailed error info: {info[0]},\n Code1:\n{solution0},\n Code2:\n{solution1} "
            return filtered, error_info
        except json.JSONDecodeError:
            return [], "Sandbox returned format cannot be parsed as JSON"

# ────────────── Main Processing Function (process_line) ──────────────
def process_line(idx, line, gen_index):
    try:
        obj = line
        typ = "stdin"
        fn_name = None
        if "type" in obj:
            typ = obj["type"]
            if typ == "function_call":
                fn_name = obj.get("fn_name")
        elif "input_output" in obj and obj["input_output"]:
            try:
                io_meta = json.loads(obj["input_output"])
                typ = "function_call" if isinstance(io_meta, dict) and "fn_name" in io_meta else "stdin"
                if typ == "function_call":
                    fn_name = io_meta["fn_name"]
            except json.JSONDecodeError:
                pass
        
        obj_clean = {
            "custom_id": obj["custom_id"],
            "question": obj["question"],
            'solutions': obj["solutions"],
            'input_generator': obj["input_generator"],
            'type': typ,
            'error_info': None,
            'input_output': obj["input_output"],
            'reward': {
                "ground_truth": {
                    "input_output": [],
                    "type": typ,
                    "fn_name": fn_name
                }
            },
            "time-limit": obj["time-limit"],
            "memory-limit": obj["memory-limit"]
        }
        ML_GEN, ML_RUN = int(obj["time-limit"]), int(obj["memory-limit"]) 
        
        # Step 1: Generate input
        input_list, obj_clean["error_info"] = generate_input(obj["custom_id"], obj["input_generator"][gen_index])
        
        if not input_list:
            inc_stats("input_failed")
            return obj_clean

        # Step 2: Generate output
        output_list, obj_clean["error_info"] = generate_output(obj["custom_id"], input_list, obj["solutions"][0], typ, fn_name)
        
        if not output_list:
            inc_stats("output_failed")
            return obj_clean

        # Step 3: Verify output consistency
        good_output_list, obj_clean["error_info"] = get_good_output(obj["custom_id"], output_list, obj["solutions"][0], obj["solutions"][-1], typ, fn_name)
        
        # Update statistics counter
        if len(good_output_list) > 0:
            inc_stats("success")
            with non_empty_lock:
                global non_empty_count
                non_empty_count += 1
        else:
            inc_stats("good_output_empty")
            
        log(f"line: {obj['custom_id']}. input_list: {len(input_list)}. output_list: {len(output_list)}. good_output_list: {len(good_output_list)}")

        obj_clean["reward"]["ground_truth"]["input_output"] = good_output_list
        return obj_clean

    except Exception as e:
        log(f"Line {idx} error: {e}")
        return None

# ────────────── Input & Deduplication Logic Functions ──────────────
def load_lines(in_path, seen_ids):
    """Load input file and deduplicate"""
    count = 0
    with open(in_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f):
            try:
                obj = json.loads(line.strip())
                if obj['custom_id'] not in seen_ids:
                    count += 1
                    yield obj
            except json.JSONDecodeError as e:
                log(f"Line {line_num+1} JSON parsing failed: {e}")
            except Exception as e:
                log(f"Line {line_num+1} processing error: {e}")

# ────────────── Main Function ──────────────
def main():
    ap = argparse.ArgumentParser(description="Parallel processing of code generation tasks")
    ap.add_argument('--input', required=True, help="Input JSONL file path")
    ap.add_argument('--output', required=True, help="Output JSONL file path")
    ap.add_argument('--gen_index', type=int, default=0, help="Use which generator (default 0)")
    ap.add_argument('--workers', type=int, default=8, help="Number of parallel worker threads (default 8)")
    args = ap.parse_args()

    print(f"Starting task processing: input={args.input}, output={args.output}, gen_index={args.gen_index}, workers={args.workers}", flush=True)
    print(f"Configuration: TL_GEN={TL_GEN}s, TL_RUN={TL_RUN}s, MAX_PARALLEL_JUDGE={MAX_PARALLEL_JUDGE}", flush=True)

    if not os.path.exists(args.input):
        print(f"[ERROR] Input file not found: {args.input}", flush=True)
        return

    # Read already processed custom_ids
    custom_id_list = set()
    if os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line.strip())
                custom_id_list.add(data['custom_id'])
        print(f"Output file exists, skipping {len(custom_id_list)} already processed entries", flush=True)

    # Use new load_lines function
    lines = list(load_lines(args.input, custom_id_list))


    print(f"Need to process {len(lines)} new entries", flush=True)
    
    if not lines:
        print("No new entries to process, program ended", flush=True)
        return

    # Check and adjust workers count
    max_workers = min(args.workers, multiprocessing.cpu_count() * 4, 64)  # Restore to reasonable limit
    if args.workers != max_workers:
        print(f"Adjusting workers count from {args.workers} to {max_workers}", flush=True)
        args.workers = max_workers
    
    # Parallel execution + real-time writing
    with open(args.output, 'a', encoding='utf-8') as fout:
        try:
            with concurrent.futures.ThreadPoolExecutor(args.workers) as ex:
                print(f"Thread pool created successfully, workers={args.workers}", flush=True)
                
                # Submit all tasks
                fut2idx = {}
                for i, ln in enumerate(lines):
                    fut = ex.submit(process_line, i, ln, args.gen_index)
                    fut2idx[fut] = i
                
                print(f"All tasks submitted, waiting for results", flush=True)

                processed_count = 0
                total_tasks = len(fut2idx)
                
                for fut in concurrent.futures.as_completed(fut2idx):
                    idx = fut2idx[fut]
                    try:
                        # Get processing result, if None return original object
                        obj = fut.result() or lines[idx]
                    except Exception as e:
                        print(f"Line {idx} error: {e}", flush=True)
                        obj = lines[idx]

                    # Real-time write and flush
                    json.dump(obj, fout, ensure_ascii=False)
                    fout.write('\n')
                    fout.flush()

                    # Update statistics
                    processed_count += 1
                    with non_empty_lock:
                        success_count = non_empty_count
                    
                    # Simple progress display
                    print(f"Progress: {processed_count}/{total_tasks} ({100*processed_count/total_tasks:.1f}%), Success: {success_count}", flush=True)
                    
                    # Print detailed statistics after each line
                    print_stats(idx)
                    
        except Exception as e:
            print(f"[ERROR] Thread pool creation failed: {e}", flush=True)
            import traceback
            print(f"[ERROR] Detailed error info: {traceback.format_exc()}", flush=True)
            
            # If failed, fall back to single-threaded processing
            print(f"Switching to single-threaded processing", flush=True)
            for i, ln in enumerate(lines):
                try:
                    obj = process_line(i, ln, args.gen_index) or ln
                    json.dump(obj, fout, ensure_ascii=False)
                    fout.write('\n')
                    fout.flush()
                    print(f"Single-threaded task {i} completed", flush=True)
                except Exception as e:
                    print(f"[ERROR] Single-threaded task {i} failed: {e}", flush=True)
                    json.dump(ln, fout, ensure_ascii=False)
                    fout.write('\n')
                    fout.flush()

    # Final statistics output
    print("\nFinal statistics:", flush=True)
    with stats_lock:
        for k, v in stats_counter.items():
            print(f"{k:<20}: {v}", flush=True)
    
    print(f"Processing completed! Number of successful entries: {non_empty_count}", flush=True)


if __name__ == "__main__":
    main()