class Dependency:

    def __init__(self, includes: {str} = None, code: str = '', dependency: 'Dependency' = None):
        # Set dependency
        self.dependency = dependency

        # Set includes
        if includes is None:
            includes = set()
        if dependency is None:
            self.includes = includes
        else:
            self.includes = (includes | dependency.includes)

        self.code = code.splitlines()

    def get_code_template(self):
        # Return plain code if no dependency
        if self.dependency is None:
            return self.code

        # If not, find the indentation of the $CODE element
        indentation = ''
        i_code = -1
        for i, line in enumerate(self.dependency.get_code_template()):
            if "$CODE" in line:
                indentation = line[:line.index("$CODE")]
                i_code = i
                break

        if i_code == -1:
            raise AssertionError("Template code of dependency should contain $CODE")

        # Indent the code
        own_code = self.code.copy()
        for i, line in enumerate(self.code):
            own_code[i] = indentation + line

        # Replace the line with $CODE with our code
        result = self.dependency.code.copy()
        return result[:i_code] + own_code + result[i_code + 1:]

    def get_final_template(self):
        template = self.get_code_template()

        # Create list
        includes = list(self.includes)
        for i, include in enumerate(includes):
            includes[i] = '#include <%s>' % include

        # Find includes in template
        for i, line in enumerate(template):
            if "$INCLUDE" in line:
                return template[:i] + includes + template[i + 1:]

        raise AssertionError("Template code should contain $INCLUDE")


if __name__ == "__main__":
    c = "$INCLUDE\ntest;\n\t    $CODE;\nint x = 3;"
    x = Dependency({'linux/ether.h'}, c)
    y = Dependency({'linux/something.h'}, "hello!\n\tCheck this cool indentation!", x)
    print("\n".join(y.get_final_template()))
