#!/usr/bin/env python3
"""
Mapper for CodeTest JSONL data to Problem dataclass format.
Converts CodeTest problems to the standardized Problem format used by the analysis webapp.
"""

import json
import pickle
import os
import sys
import argparse
import logging
from typing import List, Dict, Any
from pathlib import Path
import tqdm

# Add the parent directory to the path to import data_structures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'generation'))
from data_structures import Problem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def map_codetest_problem(problem: Dict[str, Any], idx: int) -> Problem:
    """
    Convert a CodeTest problem dictionary to our Problem data structure.
    
    Args:
        problem: Dictionary containing CodeTest problem data
        idx: Index of the problem in the dataset
        
    Returns:
        Problem dataclass instance
    """
    # Extract input/output pairs from the CodeTests field
    # CodeTest format has CodeTests as a JSON string containing input_output
    sample_inputs = []
    sample_outputs = []
    
    if "CodeTests" in problem:
        try:
            codetests = json.loads(problem["CodeTests"])
            if "input_output" in codetests:
                input_output = codetests["input_output"]
                if isinstance(input_output, list):
                    for test_case in input_output:
                        if "input" in test_case:
                            sample_inputs.append(test_case["input"])
                        if "output" in test_case:
                            sample_outputs.append(test_case["output"])
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    
    # Also check public_tests, private_tests, and generated_tests for additional test cases
    for test_type in ["public_tests", "private_tests", "generated_tests"]:
        if test_type in problem and isinstance(problem[test_type], list):
            for test_case in problem[test_type]:
                if isinstance(test_case, dict):
                    if "input" in test_case:
                        sample_inputs.append(test_case["input"])
                    if "output" in test_case:
                        sample_outputs.append(test_case["output"])
    
    # Parse time limit (e.g., 1.0 -> 1.0)
    time_limit = 2.0  # default
    if "time-limit" in problem:
        try:
            time_limit = float(problem["time-limit"])
        except (ValueError, TypeError):
            time_limit = 2.0
    
    # Parse memory limit (e.g., 128.0 -> 128)
    memory_limit = 256  # default
    if "memory-limit" in problem:
        try:
            memory_limit = int(float(problem["memory-limit"]))
        except (ValueError, TypeError):
            memory_limit = 256
    
    # Extract solutions - they're already in a list format
    solutions = problem.get("solutions", [])
    if not isinstance(solutions, list):
        solutions = []
    
    # Ensure inputs and outputs are lists of strings
    if not isinstance(sample_inputs, list):
        sample_inputs = []
    if not isinstance(sample_outputs, list):
        sample_outputs = []
    
    # Convert to strings if they aren't already
    sample_inputs = [str(inp) for inp in sample_inputs]
    sample_outputs = [str(out) for out in sample_outputs]
    
    return Problem(
        id=str(idx + 1),
        name=problem.get("custom_id", f"CodeTest Problem {idx + 1}"),
        statement=problem.get("question", ""),
        sample_inputs=sample_inputs,
        sample_outputs=sample_outputs,
        difficulty="UNKNOWN_DIFFICULTY",  # CodeTest doesn't have difficulty info
        solutions=solutions,
        time_limit=time_limit,
        memory_limit=memory_limit
    )

def load_codetest_data(jsonl_path: str) -> List[Dict[str, Any]]:
    """
    Load CodeTest data from a JSONL file.
    
    Args:
        jsonl_path: Path to the JSONL file
        
    Returns:
        List of problem dictionaries
    """
    logger = logging.getLogger(__name__)
    problems = []
    
    try:
        # First, count total lines for progress bar
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            total_lines = sum(1 for line in f if line.strip())
        
        logger.info(f"Loading {total_lines} lines from {jsonl_path}")
        
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(tqdm.tqdm(f, total=total_lines, desc="Loading JSONL"), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    problem = json.loads(line)
                    problems.append(problem)
                except json.JSONDecodeError as e:
                    logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                    continue
    except FileNotFoundError:
        logger.error(f"File {jsonl_path} not found")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading file {jsonl_path}: {e}")
        sys.exit(1)
    
    logger.info(f"Successfully loaded {len(problems)} problems")
    return problems

def map_codetest_dataset(jsonl_path: str, output_path: str) -> List[Problem]:
    """
    Map an entire CodeTest dataset to Problem format and save to pickle.
    
    Args:
        jsonl_path: Path to input JSONL file
        output_path: Path to output pickle file
        
    Returns:
        List of mapped Problem objects
    """
    logger = logging.getLogger(__name__)
    
    logger.info(f"Loading CodeTest data from {jsonl_path}")
    problems_data = load_codetest_data(jsonl_path)
    logger.info(f"Loaded {len(problems_data)} problems")
    
    logger.info("Mapping problems to Problem dataclass format...")
    mapped_problems = []
    failed_count = 0
    
    for i, problem_data in enumerate(tqdm.tqdm(problems_data, desc="Mapping problems")):
        try:
            mapped_problem = map_codetest_problem(problem_data, i)
            mapped_problems.append(mapped_problem)
        except Exception as e:
            logger.warning(f"Failed to map problem {i+1}: {e}")
            failed_count += 1
            continue
    
    logger.info(f"Successfully mapped {len(mapped_problems)} problems")
    if failed_count > 0:
        logger.warning(f"Failed to map {failed_count} problems")
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save to pickle file
    logger.info(f"Saving mapped problems to {output_path}")
    with open(output_path, 'wb') as f:
        pickle.dump(mapped_problems, f)
    
    logger.info(f"Saved {len(mapped_problems)} problems to {output_path}")
    return mapped_problems

def main():
    """Main function to run the mapper from command line."""
    logger = logging.getLogger(__name__)
    
    parser = argparse.ArgumentParser(
        description="Map CodeTest JSONL data to Problem dataclass format"
    )
    parser.add_argument(
        "input_file",
        help="Path to input JSONL file (e.g., codetest-22.jsonl)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output pickle file path (default: data/mapped_<input_filename>.pkl)"
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Data directory for output (default: data)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine input file path
    input_path = args.input_file
    if not os.path.isabs(input_path):
        # If relative path, assume it's in the data directory
        input_path = os.path.join(os.path.dirname(__file__), "..", "data", args.input_file)
    
    # Determine output file path
    if args.output:
        output_path = args.output
    else:
        # Generate output filename based on input filename
        input_filename = os.path.basename(args.input_file)
        output_filename = f"mapped_{os.path.splitext(input_filename)[0]}.pkl"
        output_path = os.path.join(os.path.dirname(__file__), "..", args.data_dir, output_filename)
    
    # Convert to absolute paths
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)
    
    logger.info(f"Input file: {input_path}")
    logger.info(f"Output file: {output_path}")
    
    # Check if input file exists
    if not os.path.exists(input_path):
        logger.error(f"Input file {input_path} does not exist")
        sys.exit(1)
    
    # Map the dataset
    try:
        mapped_problems = map_codetest_dataset(input_path, output_path)
        
        # Print summary
        logger.info("Mapping completed successfully!")
        logger.info(f"Total problems processed: {len(mapped_problems)}")
        logger.info(f"Output saved to: {output_path}")
        
        # Show sample of first problem
        if mapped_problems:
            logger.info("Sample problem (first one):")
            sample = mapped_problems[0]
            logger.info(f"  ID: {sample.id}")
            logger.info(f"  Name: {sample.name}")
            logger.info(f"  Time limit: {sample.time_limit}s")
            logger.info(f"  Memory limit: {sample.memory_limit}MB")
            logger.info(f"  Sample inputs: {len(sample.sample_inputs)}")
            logger.info(f"  Sample outputs: {len(sample.sample_outputs)}")
            logger.info(f"  Solutions: {len(sample.solutions)}")
            
    except Exception as e:
        logger.error(f"Error during mapping: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
