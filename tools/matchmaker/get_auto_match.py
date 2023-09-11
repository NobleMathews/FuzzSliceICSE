libraries = ["openssl", "openssh-portable", "tmux"]
def find_sub_list(sl,l):
    results=[]
    sll=len(sl)
    if sll == 0:
        return None
    for ind in (i for i,e in enumerate(l) if e==sl[0]):
        if l[ind:ind+sll]==sl:
            results.append((ind,ind+sll-1))

    return results
for test_library in libraries:
    print()
    lib_clone_location = f"/mnt/fresh/{test_library}"
    past_clone_location = f"/mnt/past/{test_library}"
    with open(f"tools/matchmaker/{test_library}", "r", encoding="UTF-8") as f:
        lines = f.readlines()
    for line in lines:
        with open(f"{lib_clone_location}/{line.split(':')[0]}", "r", encoding="UTF-8") as f:
            match_lines = f.readlines()[int(line.split(':')[2]):int(line.split(':')[1])]
        new_target = None
        with open(f"{past_clone_location}/{line.split(':')[0]}", 'r') as file_info:
            info_file = file_info.readlines()
            new_target = find_sub_list(match_lines, info_file)
            if new_target is None:
                print(line.strip(), "@=[]=====>")
                continue
            assert(len(new_target)==1)
            target = new_target[0][1]
        # print(line.strip(), f"{line.split(':')[0]}:{target}")
        print(target)
