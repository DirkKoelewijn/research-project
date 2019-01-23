from os import listdir
from os.path import isfile, join


def file_str(f_name: str) -> str:
    """
    Reads a file into a string

    :param f_name: Relative path to file
    :return: File as string
    """
    with open(f_name, 'r') as f:
        return ''.join(f.readlines())


def files_in_folder(folder: str, ext: str = None) -> [str]:
    """
    Returns the names of all all_files in a given folder

    :param folder: Folder
    :param ext: Optional. Filter on this extension (starting with .) and remove extension from file names
    :return: List of file names
    """
    if ext is None:
        return sorted([f for f in listdir(folder) if isfile(join(folder, f))])
    else:
        return sorted(
            [f.replace(ext, '') for f in listdir(folder) if isfile(join(folder, f)) and f.endswith(ext)])


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


def merge_csv_files(folder, header, out='combined'):
    files = ['%s/%s.csv' % (folder, f) for f in files_in_folder(folder, '.csv')]
    csv_lines = [','.join(header)] + [file_str(f) for f in files]
    csv_lines = '\n'.join(csv_lines)
    with open('%s/%s.csv' % (folder, out), 'w') as file:
        file.writelines(csv_lines)


if __name__ == '__main__':
    merge_csv_files('results',
                    ['name', 'protocol', 'src_ips', 'src_ports', 'dst_ports', 'TP', 'FP', 'UP', 'TN', 'FN', 'UN'],
                    out='combined/less_strict')
