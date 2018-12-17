def file_lines(f_name: str) -> [str]:
    with open(f_name, 'r') as f:
        return f.readlines()


# Return files without end of line
def file_lines_(f_name: str) -> [str]:
    return [l.replace('\n', '') for l in file_lines(f_name)]


def file_str(f_name: str) -> str:
    return ''.join(file_lines(f_name))
