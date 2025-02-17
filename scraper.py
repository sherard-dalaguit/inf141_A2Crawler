import re
import string
from collections import Counter
from urllib.parse import urlparse, urlunparse, urljoin
from bs4 import BeautifulSoup

# global data structures to keep track of information for the required report
unique_pages = set()
word_counter = Counter()
longest_page = {"url": "", "word_count": 0}
ics_subdomains = {}

# this was the default list from www.ranks.nl/stopwords
stopwords_str = """a about above after again against all am an and any are aren't as at be because been before being
below between both but by can't cannot could couldn't did didn't do does doesn't doing don't down during each few for
from further had hadn't has hasn't have haven't having he he'd he'll he's her here here's hers herself him himself his
how how's i i'd i'll i'm i've if in into is isn't it it's its itself let's me more most mustn't my myself no nor not of
off on once only or other ought our ours ourselves out over own same shan't she she'd she'll she's should shouldn't so
some such than that that's the their theirs them themselves then there there's these they they'd they'll they're they've
this those through to too under until up very was wasn't we we'd we'll we're we've were weren't what what's when when's
where where's which while who who's whom why why's with won't would wouldn't you you'd you'll you're you've your yours
yourself yourselves
"""
STOP_WORDS = {word.strip() for word in stopwords_str.split() if word.strip() != ""}


def scraper(url, resp) -> list[str]:
    """
    Main scraper function.
        - Extracts links from the given response.
        - Processes page content if the response status is 200 and content-type is HTML.
    Returns:
         A list of URLs (strings) extracted from the page that are valid per our domain restrictions.
    """
    links = extract_next_links(url, resp)

    # checks if response is valid HTML before processing the page content
    content_type = resp.raw_response.headers.get('Content-Type', '').lower()
    if resp.status == 200 and 'text/html' in content_type:
        process_page(url, resp.raw_response.content)

    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp) -> list[str]:
    """
    Extracts and defragments URLs from the response content.
    Returns a list of URLs (strings).
    """
    links = []
    if resp.status != 200:
        return links

    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    for html_tag in soup.find_all('a', href=True):
        href = urljoin(url, html_tag['href'])

        # breaking down link into its components
        parsed_url = urlparse(href)
        # url without the fragment included
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            parsed_url.query,
            ""
        ))

        links.append(new_url)
    return links


def process_page(url, content) -> None:
    """
    Processes the page content:
        - Updates the set of unique pages (using defragmented URLs).
        - Extracts text, tokenizes (removing punctuation and stop words), and updates the word frequency counter.
        - Updates the longest page information.
        - Records subdomain information for pages in ics.uci.edu.
    """
    global longest_page, word_counter, unique_pages, ics_subdomains

    parsed_url = urlparse(url)
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        parsed_url.query,
        ""
    ))
    unique_pages.add(new_url)

    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()

    # remove punctuation and make it lowercase
    translator = str.maketrans('', '', string.punctuation)
    text_clean = text.translate(translator).lower()

    # tokenize & filter out stop words, then update word frequency counter
    words = [word for word in text_clean.split() if word not in STOP_WORDS]
    num_words = len(words)
    word_counter.update(words)

    if num_words > longest_page["word_count"]:
        longest_page["word_count"] = num_words
        longest_page["url"] = new_url

    # record subdomain if url is within ics.uci.edu
    # based on instructions, i assume that i didn't need to do this for the other domains like stat.uci.edu
    hostname = parsed_url.hostname.lower() if parsed_url.hostname else ""
    if hostname.endswith('ics.uci.edu'):
        if hostname == "ics.uci.edu":
            subdomain = "ics"
        else:
            subdomain = hostname[:-len('.ics.uci.edu')]
            # removes any trailing periods (i.e. 'www.' turns into 'www')
            if subdomain.endswith('.'):
                subdomain = subdomain[:-1]
            if not subdomain:
                subdomain = "ics"
        if subdomain not in ics_subdomains:
            ics_subdomains[subdomain] = set()
        ics_subdomains[subdomain].add(new_url)


def is_valid(url) -> bool:
    """
    Returns True if the URL is within one of the allowed domains and doesn't point to a disallowed file type.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False

        valid_domains = ('ics.uci.edu', 'cs.uci.edu', 'informatics.uci.edu', 'stat.uci.edu')
        if not any(parsed.hostname.lower().endswith(domain) for domain in valid_domains):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print("TypeError for ", parsed)
        raise


def get_top_50_words() -> list[tuple[str, int]]:
    """
    Returns a list of tuples for the top 50 most common words and their counts.
    """
    return word_counter.most_common(50)


def generate_report() -> str:
    """
    Generates a report string that includes:
        - Total unique pages
        - The longest page (by word count)
        - The top 50 most common words
        - Subdomains in ics.uci.edu and the number of unique pages in each.
    """
    report_lines = []
    report_lines.append(f"Total Unique Pages: {len(unique_pages)}")
    report_lines.append(f"Longest Page (by word count): {longest_page['url']} with {longest_page['word_count']} words")
    report_lines.append("\nTop 50 Most Common Words:")
    for word, count in get_top_50_words():
        report_lines.append(f"{word}: {count}")
    report_lines.append("\nSubdomains in ics.uci.edu:")
    for subdomain in sorted(ics_subdomains.keys()):
        url_prefix = f"http://{subdomain}.ics.uci.edu" if subdomain != "ics" else "http://ics.uci.edu"
        report_lines.append(f"{url_prefix}, {len(ics_subdomains[subdomain])}")

    report = "\n".join(report_lines)

    # save report to a file
    with open("report.txt", "w") as file:
        file.write(report)

    return report
