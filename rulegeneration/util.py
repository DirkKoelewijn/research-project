def file_str(f_name: str) -> str:
    """
    Reads a file into a string

    :param f_name: Relative path to file
    :return: File as string
    """
    with open(f_name, 'r') as f:
        return ''.join(f.readlines())
