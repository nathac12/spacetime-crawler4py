import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from tokenizer import PartA, PartB

# ANALYTICS FUNTIONS ideas 
ANALYTICS_FILE = "analytics.json"

def load_analytics():
    return None
STOP_WORDS = {
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and',
    'any', 'are', "aren't", 'as', 'at', 'be', 'because', 'been', 'before', 'being',
    'below', 'between', 'both', 'but', 'by', "can't", 'cannot', 'could', "couldn't",
    'did', "didn't", 'do', 'does', "doesn't", 'doing', "don't", 'down', 'during',
    'each', 'few', 'for', 'from', 'further', 'had', "hadn't", 'has', "hasn't",
    'have', "haven't", 'having', 'he', "he'd", "he'll", "he's", 'her', 'here',
    "here's", 'hers', 'herself', 'him', 'himself', 'his', 'how', "how's", 'i',
    "i'd", "i'll", "i'm", "i've", 'if', 'in', 'into', 'is', "isn't", 'it', "it's",
    'its', 'itself', "let's", 'me', 'more', 'most', "mustn't", 'my', 'myself',
    'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought',
    'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same', "shan't", 'she',
    "she'd", "she'll", "she's", 'should', "shouldn't", 'so', 'some', 'such', 'than',
    'that', "that's", 'the', 'their', 'theirs', 'them', 'themselves', 'then',
    'there', "there's", 'these', 'they', "they'd", "they'll", "they're", "they've",
    'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was',
    "wasn't", 'we', "we'd", "we'll", "we're", "we've", 'were', "weren't", 'what',
    "what's", 'when', "when's", 'where', "where's", 'which', 'while', 'who',
    "who's", 'whom', 'why', "why's", 'with', "won't", 'would', "wouldn't", 'you',
    "you'd", "you'll", "you're", "you've", 'your', 'yours', 'yourself',
    'yourselves'
}


def save_analytics(analytics):
    return None
    
def update_analytics(webFile):
    tokenList = PartA.tokenize(webFile)
    tokenFreq = PartA.compute_word_frequencies(tokenList)
    workCount = 0
    for token, count in tokenFreq.items():
        if not (token in STOP_WORDS) : 
            wordCount += count
    return wordCount




def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    linkList = []
    if resp.status != 200:
        print(resp.error)
        return linkList 

    pageContent = resp.raw_response.content 
    soup = BeautifulSoup(pageContent, 'html.parser')
    pageText = soup.get_text()
    #check for word count
    word_count = update_analytics(pageText)

    #check for low info content (trap detection)
    if word_count < 100: #random # we need to decide a number i think
        print(f"({word_count}) word count is low info content for {url}, skipping")
        return linkList
    
    for tag in soup.find_all('a', href=True):
        href = tag.get('href').strip()
    
        full_link = urljoin(url, href)
        clean_link, _ = urldefrag(full_link)
        
        if clean_link.startswith("http://") or clean_link.startswith("https://"): #updated changes
            linkList.append(clean_link)

    return linkList

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False

        host = parsed.netloc.lower()
        
        regExp = r"^.*\.(ics|cs|informatics|stat)\.uci\.edu$"  #updated?
        regExp2 = r"^(ics|cs|informatics|stat)\.uci\.edu$"
        if not (re.match(regExp, parsed.netloc) or re.match(regExp2, parsed.netloc)):
            return False

        
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            return False
       
        #some trap detection patterns
        trap_patterns = [
            r'/tag/',
            r'\?share=',
            r'\?page=\d+',
            r'/feed/',
            r'\?version=',
            r'/wp-json/',
        ]
        
        for pattern in trap_patterns:
            if re.search(pattern, url.lower()):
                return False
        
        path_seg = [seg for seg in parsed.path.split('/') if seg]
        
        if len(path_seg) > 10:
            return False
            
        if len(url) > 200:
            return False
            
        return True
        
    except TypeError:
        print ("TypeError for ", parsed)
        raise

