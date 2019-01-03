def file_str(f_name: str) -> str:
    """
    Reads a file into a string

    :param f_name: Relative path to file
    :return: File as string
    """
    with open(f_name, 'r') as f:
        return ''.join(f.readlines())


def code_insert(code: str, marker: str, new_code: str, replace=True):
    """
    Inserts new code in existing code.

    :param code: Existing code containing marker
    :param marker: Marker where to insert code
    :param new_code: New code to insert
    :param replace: Replaces the marker if true, or insert the code before the marker if false
    :return: Existing code with new code inserted
    """
    # Split current code by lines
    code_lines = code.splitlines(False)
    for i, line in enumerate(code_lines):
        if marker in line:
            indent = line[:line.find(marker)]
            own_code = [indent + l for l in new_code.splitlines(False)]
            if replace:
                code_lines = code_lines[:i] + own_code + code_lines[i + 1:]
            else:
                code_lines = code_lines[:i] + own_code + code_lines[i:]

    return "\n".join(code_lines)
