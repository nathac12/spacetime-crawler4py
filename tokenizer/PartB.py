from . import PartA as A

def compareFile(file_1, file_2):
    """
    Time complexity: O(n+m)
    
    The time complexity is O(n+m) where n is the length of the first document 
    and m is the length of the second document. This is because each file is parsed in n
    time and then the set operation also takes n time. This makes the full operation a
    multiple of n or m and thus n+m time.
    """

    file1_tokens = A.tokenize(file_1)
    file2_tokens = A.tokenize(file_2)

    file1_words = set(file1_tokens)
    file2_words = set(file2_tokens)

    return len(file1_words & file2_words)

