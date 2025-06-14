from cli import parse_args, run_scan

if __name__ == "__main__":
    args = parse_args()
    run_scan(args.url, verbose=args.verbose)
