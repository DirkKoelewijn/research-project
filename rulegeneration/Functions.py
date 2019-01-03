from util import file_str


class Function:
    """
    Class to hold functions. This functions may be required by certain properties.
    """

    def __init__(self, name, code=None, file=None):
        self.name = name
        if code is not None:
            self.code = code
        elif file is not None:
            self.code = file_str(file)
        else:
            raise AssertionError('File or code should be specified')

    def __str__(self):
        return self.code

    def __repr__(self):
        return self.name


# Function to compare two mac addresses (for Ethernet)
CompareMAC = Function('compare_mac', file='templates/compare_mac.c')
