libraries = ["openssl", "openssh-portable", "tmux"]
for test_library in libraries:
    print()
    with open(f"tools/matchmaker/past/{test_library}_past", "r", encoding="UTF-8") as f:
        lines = f.readlines()
    for line in lines:
        with open(f"tools/matchmaker/past/{test_library}_rats", "r", encoding="UTF-8") as f:
            if line.strip() in f.read():
                print(1, end="\t")
            else:
                print(0, end="\t")
        with open(f"tools/matchmaker/past/{test_library}_infer", "r", encoding="UTF-8") as f:
            if line.strip() in f.read():
                print(1, end="\n")
            else:
                print(0, end="\n")
