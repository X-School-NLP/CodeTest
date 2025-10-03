import argparse
import json

def truncate_json(obj, limit=100):
    """Recursively truncate strings in a JSON object for preview."""
    if isinstance(obj, dict):
        return {k: truncate_json(v, limit) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [truncate_json(v, limit) for v in obj]
    elif isinstance(obj, str):
        return obj[:limit] + ("..." if len(obj) > limit else "")
    else:
        return obj  # keep numbers, bools, null as-is

def get_line_count(path: str) -> None:
    counter = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            counter += 1
    
    print(f"Number of lines {counter}")


def show_first_line_as_json(path: str, limit: int = 100) -> None:
    with open(path, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()

    obj = json.loads(first_line)
    truncated_obj = truncate_json(obj, limit)
    print(json.dumps(truncated_obj, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Read the first line of a JSONL file and pretty-print it as JSON (truncated)"
    )
    parser.add_argument("file", help="Path to the .jsonl file")
    parser.add_argument(
        "--limit", "-n",
        type=int,
        default=100,
        help="Number of characters to show per string in JSON (default: 100)"
    )
    args = parser.parse_args()

    show_first_line_as_json(args.file, args.limit)
    get_line_count(args.file)
