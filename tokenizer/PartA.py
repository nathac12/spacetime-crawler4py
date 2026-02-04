import sys
import os
from collections import defaultdict
from typing import List, Dict

def tokenize(webFile) -> List[str]:
    """
    Runtime Complexity: O(n)

    This method is O(n) because we are going through every character individually
    and each character is read and processed only once. When processing, append and checking
    for an ascii letter are both O(1) and each character is only joined one time each, which is O(n).

    :param file_path: Path to the text file to be read
    :return: List of tokens in the file
    """
    tokens = []
    current = [] #use to read characters 1by1

    with webFile as f:
        for line in f: #for each character in each line
            for char in line.lower():
                if 'a' <= char <= 'z' or '0' <= char <= '9': #if its a letter/number we append it to the word we are reading
                    current.append(char)
                else:
                    if current: #if we hit a delimiter or non alphanumeric -> add word to tokens
                        tokens.append("".join(current))
                        current = [] #clear current

    if current:
        tokens.append("".join(current)) #clear last word in current
        current = []

    return tokens

def compute_word_frequencies(tokens: List[str]) -> Dict[str, int]:
    """
    Runtime Complexity: O(n) where n is the length of the tokens list

    The runtime is O(n) because it goes through each item in the tokens list once.

    :param tokens: List of tokens
    :return: Dictionary of word frequencies
    """
    frequencies = defaultdict(int)
    for token in tokens:
        if token in frequencies:
            frequencies[token] += 1
        else:
            frequencies[token] = 1

    return frequencies

def print_frequencies(frequencies: Dict[str, int]) -> None:
    """
    Runtime Complexity: O(nlogn) where n is the length of the tokens list

    This is O(nlogn) because we sort in nlogn time. Then we print in n time by going over the array,
    which is 2nlogn and becomes nlogn.

    Prints the frequency of each token in <token> - <freq> format

    :param frequencies: dictionary of word frequencies/number of occurrences
    :return:
    """

    items = frequencies.items()
    items_sorted = sorted(items, key=lambda x:x[1], reverse=True)

    for token, count in items_sorted:
        print(f"{token} - {count}")
