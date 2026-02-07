import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlencode
from bs4 import BeautifulSoup
from lxml import html
import PartA as A
from typing import List, Dict
import logging 
from collections import Counter, defaultdict
import os
import json

logging.basicConfig(
    filename='crawler.log',
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

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

data = {
    'urls': set(),
    'longest': {'url': '', 'count': 0},
    'words': Counter(),
    'subs': defaultdict(set)
}

DATA_FILE = 'data.json'

#didnt double check my code
def load_data(): 
    global data
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                saved = json.load(f)
                data['urls'] = set(saved.get('urls', []))
                data['longest'] = saved.get('longest', {'url': '', 'count': 0})
                data['words'] = Counter(saved.get('words', {}))
                sub_data = saved.get('subs', {})
                data['subs'] = defaultdict(set)
                for sub, pages in sub_data.items():
                    data['subs'][sub] = set(pages)
        except Exception as e:
            logger.error(f"Error loading data: {e}")

def save_data():
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump({
                'urls': list(data['urls']),
                'longest': data['longest'],
                'words': dict(data['words']),
                'subs': {k: list(v) for k, v in data['subs'].items()}
            }, f)
    except Exception as e:
        logger.error(f"Error saving data: {e}")


def update_data(url, word_count, tokenFreq):
# track longest page
    if word_count > data['longest']['count']:
        data['longest'] = {'url': url, 'count': word_count}
        
        # update word frequencies
    for token, count in tokenFreq.items():
        if token not in STOP_WORDS:
            data['words'][token] += count

    sub = get_subdomain(url)
        if sub:
            data['subs'][sub].add(url)
        
def get_subdomain(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()

        if netloc.startswith('www.'):
            netloc = netloc[4:]
        if netloc.endswith('.uci.edu'):
            return netloc
        return None
    except:
        return None

def tokenize(text: str) -> List[str]:
    tokens = []
    current = []

    for char in text.lower():
        if 'a' <= char <= 'z' or '0' <= char <= '9':
            current.append(char)
        else:
            if current:
                tokens.append("".join(current))
                current = []

    if current:
        tokens.append("".join(current))

    return tokens

def tokenize_soup(soup: BeautifulSoup) -> List[str]:
    for tag in soup(["script", "style", "noscript", "iframe"]):
        tag.decompose() #takes the items that arent important text ie css and removes them basically

    text = soup.get_text(separator=" ") #pulls out text and seperates it with a space so we can tokenize it
    text = re.sub(r"\s+", " ", text).strip()  #\s+ = multiple spaces/newlines/tabs -> replaces any whitepspace with a single space

    return tokenize(text)

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
        logger.debug(f"Got status {resp.status} for {url}")
        return linkList 
        
    if not resp.raw_response or not resp.raw_response.content:
        logger.debug(f"No content for {url}")
        return linkList
        
    #duplicate page
    if url in data['urls']:
        logger.debug(f"Duplicate page skipped: {url}")
        return []
    data['urls'].add(url) #marks page as seen
    
    try:
        pageContent = resp.raw_response.content 
        soup = BeautifulSoup(pageContent, 'lxml')
    
        #check for word count
        soup_tokens = tokenize_soup(soup)
        tokenFreq = A.compute_word_frequencies(soup_tokens) #there is no function to call this?
        word_count = 0
        for token, count in tokenFreq.items():
            if not (token in STOP_WORDS) : 
                word_count += count
        #check for low info content (trap detection)
        
        if word_count < 50:
            logger.info(f"Only {word_count} words on {url}, skipping")
            return linkList
            
        update_data(url, word_count, tokenFreq)

        for tag in soup.find_all('a', href=True):
            href = tag.get('href').strip()
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
            full_link = urljoin(url, href)
            clean_link, _ = urldefrag(full_link)
            if clean_link.startswith("http://") or clean_link.startswith("https://"):
                linkList.append(clean_link)
    
    except Exception as e:
        logger.error(f"Error processing {url}: {e}")
        return linkList

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
        if not (re.match(regExp, host) or re.match(regExp2, host)):
            return False

        '''
        if parsed.netloc not in set(["ics.uci.edu", "cs.uci.edu ", "informatics.uci.edu ", "stat.uci.edu"]):
            return False
        not sure if this is correct
        '''
        #regex should cover it
        
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
            r'\bpage=\d+',
            r'/feed/',
            r'\?version=',
            r'/wp-json/',
            r'/calendar/',
            r'\?action=',
            r'\?format=',
            r'/print/',
            r'\?print=',
            r'/pdf/',
            r'/download/',
            r'/attachment/'
            r'\?replytocom=',
            r'/comment-page-',
            r'\?like=',
            r'\?login=',
            r'/trackback/',
            r'\?filter=',
            r'\?sort=',
            r'\?order='
        ]
        
        for pattern in trap_patterns:
            if re.search(pattern, url.lower()):
                logger.debug(f"Trap pattern blocked: {url}")
                return False
                
        if re.search(r'tribe-bar-date=\d{4}-\d{2}-\d{2}', url):
            logger.debug(f"Calendar date trap blocked: {url}")
            return False

        query_lower = parsed.query.lower()
        if 'do=media' in query_lower:
            param_count = query_lower.count('&') + 1
            if param_count > 3:
                logger.debug(f"Media manager variation blocked: {url}")
                return False
            
        #repeated path segments
        path_seg = [seg for seg in parsed.path.split('/') if seg]
        if len(path_seg) != len(set(path_seg)):
            logger.debug(f"Repeated path segment trap blocked: {url}")
            return False
        
        if len(path_seg) > 10:
            logger.info(f"Path too deep blocked: {url}")
            return False
            
        if len(url) > 200:
            logger.info(f"URL too long blocked: {url}")
            return False
        
        query = parsed.query.lower()
        if query:
            # Too many query parameters is suspicious
            if query.count('&') > 5:
                logger.debug(f"Too many query params: {url}")
                return False
            
            #check for session IDs & other trap
            trap_params = ['sessionid', 'sid', 'phpsessid', 'jsessionid']
            if any(param in query for param in trap_params):
                logger.debug(f"Session ID in URL: {url}")
                return False
                
        return True
        
    except Exception as e:
        logger.error(f"Error Parsing URL {url}: {e}")
        return False

load_data()








