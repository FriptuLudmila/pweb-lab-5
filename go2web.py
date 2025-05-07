#!/usr/bin/env python3
# Usage: go2web -u <URL> | go2web -s <search-term> | go2web -h
import argparse
import socket
import ssl
import re
import json
import os
import hashlib
import time
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup

# Constants
MAX_REDIRECTS = 5
CACHE_VALIDITY_SECONDS = 3600  # 1 hour
MAX_SEARCH_RESULTS = 10
USER_AGENT = "Mozilla/5.0 (compatible; go2web/1.0)"
SOCKET_TIMEOUT = 10  # prevents hanging on slow connections


def parse_arguments():
    # Parse command line arguments for go2web.
    parser = argparse.ArgumentParser(add_help=False, description='CLI tool for making HTTP requests')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    parser.add_argument('-u', '--url', help='Make an HTTP request to the specified URL')
    parser.add_argument('-s', '--search', help='Search term using your favorite search engine', nargs='+')
    parser.add_argument('-f', '--force', action='store_true', help='Force refresh, ignore cache')
    args = parser.parse_args()

    # Handle help flag
    if args.help:
        print("go2web - CLI tool for making HTTP requests")
        print("Usage:")
        print("  go2web -u <URL>         # make an HTTP request to the specified URL and print the response")
        print(
            "  go2web -s <search-term> # make an HTTP request to search the term using your favorite search engine and print top 10 results")
        print("  go2web -f               # force refresh, ignore cache")
        print("  go2web -h               # show this help")
        exit(0)

    # Check if at least one of -u or -s is provided
    if not args.url and not args.search:
        print("Error: Either -u or -s must be provided.")
        print("Use 'go2web -h' for help.")
        exit(1)

    return args


def parse_url(url):
    # Parses a URL into components needed for HTTP requests.

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Default to HTTPS

    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path if parsed_url.path else '/'
    query = '?' + parsed_url.query if parsed_url.query else ''
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    is_https = parsed_url.scheme == 'https'

    return host, path + query, port, is_https


def make_http_request(url, max_redirects=MAX_REDIRECTS):
    """
    Make an HTTP request to the specified URL and return the HTTP response as a string
    """
    redirects = 0
    original_url = url

    while redirects <= max_redirects:
        host, path, port, is_https = parse_url(url)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # ipv4 adressing is used
        s.settimeout(SOCKET_TIMEOUT) # creates TCP socket

        try:
            # Connect to the server
            try:
                s.connect((host, port))
            except socket.gaierror:
                raise Exception(f"Could not resolve host: {host}")
            except socket.timeout:
                raise Exception(f"Connection timed out for host: {host}")

            # Wrap socket with SSL if HTTPS
            if is_https:
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=host)

            # Create HTTP request with Accept header for content negotiation
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Accept: text/html, application/json\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Connection: close\r\n\r\n"
            )

            # Send request
            s.sendall(request.encode())

            # Receive and process response
            response = b""
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break

            response_str = response.decode('utf-8', errors='ignore')

            # Check for redirects
            status_match = re.search(r'HTTP/1\.[01] (\d+)', response_str)
            if status_match and status_match.group(1) in ('301', '302', '303', '307', '308'):
                redirects += 1
                location_match = re.search(r'Location: (.*?)\r\n', response_str, re.IGNORECASE)
                if location_match:
                    new_url = location_match.group(1).strip()
                    # Handle relative URLs
                    if new_url.startswith('/'):
                        protocol = 'https://' if is_https else 'http://'
                        new_url = f"{protocol}{host}{new_url}"
                    # Handle URLs without protocol
                    elif not new_url.startswith(('http://', 'https://')):
                        protocol = 'https://' if is_https else 'http://'
                        new_url = f"{protocol}{host}/{new_url}"

                    print(f"Redirected to: {new_url}")
                    url = new_url
                    continue

            return response_str
        except Exception as e:
            raise e
        finally:
            s.close()

    raise Exception(f"Too many redirects when requesting {original_url}")


def parse_http_response(response):
    """
    Parse an HTTP response into a human-readable format and return human-readable content
    """
    # Split headers and body
    headers_end = response.find('\r\n\r\n')
    if headers_end == -1:
        return "Invalid HTTP response"

    headers = response[:headers_end]
    body = response[headers_end + 4:]

    # Extract status code
    status_match = re.search(r'HTTP/1\.[01] (\d+)', headers)
    status_code = int(status_match.group(1)) if status_match else 0

    # Check content type
    content_type_match = re.search(r'Content-Type: (.*?)\r\n', headers, re.IGNORECASE)
    content_type = content_type_match.group(1) if content_type_match else ""

    # Handle transfer encoding (chunked)
    transfer_encoding = re.search(r'Transfer-Encoding: (.*?)\r\n', headers, re.IGNORECASE)
    if transfer_encoding and 'chunked' in transfer_encoding.group(1).lower():
        body = decode_chunked(body)

    # Handle Content-Encoding
    if 'text/html' in content_type.lower():
        # BeautifulSoup to parse HTML
        soup = BeautifulSoup(body, 'html.parser')

        # Remove script, style, and other non-content tags
        for tag in soup(['script', 'style', 'meta', 'link', 'svg', 'iframe', 'noscript']):
            tag.extract()

        # Format the content
        formatted_content = format_html_content(soup)
        if status_code != 0:
            formatted_content = f"Status: {status_code}\n\n" + formatted_content
        return formatted_content

    elif 'application/json' in content_type.lower():
        try:
            data = json.loads(body)
            return json.dumps(data, indent=2)
        except json.JSONDecodeError:
            return body

    return body


def decode_chunked(body):
    """
    Decode a chunked HTTP response body.
    """
    decoded = ""
    pos = 0

    while pos < len(body):
        # Find the chunk size (hex)
        chunk_size_end = body.find('\r\n', pos)
        if chunk_size_end == -1:
            break

        try:
            chunk_size = int(body[pos:chunk_size_end], 16)
        except ValueError:
            break

        if chunk_size == 0:
            break  # Last chunk

        # Extract the chunk data
        chunk_start = chunk_size_end + 2
        chunk_end = chunk_start + chunk_size

        if chunk_end > len(body):
            break  # Incomplete chunk

        decoded += body[chunk_start:chunk_end]
        pos = chunk_end + 2  # Skip CRLF after chunk

    return decoded


def format_html_content(soup):
    """
    Format HTML content into a human-readable text representation.
    """
    # Extract title
    title = soup.title.text.strip() if soup.title else "No Title"

    # Text extraction
    output_parts = [f"TITLE: {title}", ""]

    # Extract headings for structure
    headings = []
    for h in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
        level = int(h.name[1])
        indent = "  " * (level - 1)
        text = h.get_text().strip()
        if text:
            headings.append(f"{indent}{text}")

    if headings:
        output_parts.extend(["HEADINGS:", *headings, ""])

    # Get all text from all visible elements
    content_parts = []
    for element in soup.find_all(['p', 'div', 'span', 'a', 'li', 'td', 'th',
                                  'strong', 'em', 'b', 'i', 'label', 'button',
                                  'section', 'article', 'header', 'footer']):
        text = element.get_text().strip()
        if text and len(text) > 5:  # Skip very short content
            # Simple deduplication - don't add exact matches
            if not any(part == text for part in content_parts):
                content_parts.append(text)

    # Add content to output with sectioning
    if content_parts:
        output_parts.append("CONTENT:")
        for part in content_parts:
            output_parts.append(part)
            output_parts.append("")  # Add spacing between content blocks

    # Find images and their alt text or src
    images = []
    for img in soup.find_all('img'):
        alt = img.get('alt', '').strip()
        src = img.get('src', '').strip()
        if alt and len(alt) > 3:  # important alt text
            images.append(f"[Image: {alt}]")
        elif src:
            # Extract just the filename from src
            filename = src.split('/')[-1].split('?')[0]
            if filename:
                images.append(f"[Image: {filename}]")

    if images:
        output_parts.extend(["", "IMAGES:"])
        output_parts.extend(images)

    # Extract links
    links = []
    for a in soup.find_all('a', href=True):
        href = a.get('href')
        text = a.get_text().strip()
        if href and text and len(text) > 1:
            # Only include links with text and handle relative links
            if not href.startswith(('http://', 'https://')):
                # Skip anchor links and javascript
                if href.startswith('#') or href.startswith('javascript:'):
                    continue
            links.append(f"- {text}: {href}")

    if links:
        output_parts.extend(["", "LINKS:"])
        output_parts.extend(links)

    return "\n\n".join(output_parts)


def extract_url_from_redirect(href):
    """
    Extract the actual URL from a search engine redirect URL.
    """
    if '/l/?uddg=' in href:
        try:
            href_parts = urlparse(href)
            query_params = dict(param.split('=') for param in href_parts.query.split('&'))
            if 'uddg' in query_params:
                return unquote(query_params['uddg'])
        except Exception:
            pass
    return href


def process_search_results(results, soup, selector, title_selector=None, link_selector=None):
    """
    Process search results from HTML using CSS selectors.

    Args:
        results (list): Current list of results (title, url) tuples
        soup (BeautifulSoup): The parsed HTML
        selector (str): CSS selector for result containers
        title_selector (str, optional): CSS selector for title element
        link_selector (str, optional): CSS selector for link element

    Returns: Updated list of results
    """
    for result in soup.select(selector):
        # Extract title element
        if title_selector:
            title_elem = result.select_one(title_selector)
            if not title_elem:
                continue
        else:
            title_elem = result

        # Extract link element
        if link_selector:
            link_elem = title_elem.select_one(link_selector)
        else:
            link_elem = title_elem.find('a')

        if not link_elem or not link_elem.has_attr('href'):
            continue

        href = extract_url_from_redirect(link_elem['href'])
        title = title_elem.get_text().strip()

        if href and title and len(title) > 3:
            if href not in [r[1] for r in results] and len(results) < MAX_SEARCH_RESULTS:
                results.append((title, href))

    return results


def search(term):
    """
    Search the web using a search engine.

    Args:term (list): Search terms as a list of strings

    """
    search_term = '+'.join(term)
    url = f"https://duckduckgo.com/html/?q={search_term}"

    try:
        response = make_http_request(url)

        # Split headers and body
        headers_end = response.find('\r\n\r\n')
        if headers_end == -1:
            return "Invalid HTTP response"

        body = response[headers_end + 4:]

        # Raw HTML for debugging
        debug_path = os.path.join(get_cache_path(), "last_search_debug.html")
        with open(debug_path, 'w', encoding='utf-8') as f:
            f.write(body)

        # Parse the HTML response
        soup = BeautifulSoup(body, 'html.parser')

        # Find search results
        results = []

        # Method 1: Standard DuckDuckGo HTML structure
        results = process_search_results(
            results, soup, '.result__body', '.result__title', 'a'
        )

        # Method 2: Alternative DuckDuckGo HTML structure
        if not results:
            results = process_search_results(
                results, soup, '.links_main', 'a'
            )

        # Method 3: Get all external links
        if not results:
            for a_tag in soup.find_all('a', href=True):
                href = extract_url_from_redirect(a_tag['href'])
                title = a_tag.get_text().strip()

                # Skip internal navigation, empty titles
                if (title and len(title) > 3 and not title.isdigit() and
                        href and href.startswith(('http://', 'https://')) and
                        'duckduckgo.com' not in href and
                        href not in [r[1] for r in results] and
                        len(results) < MAX_SEARCH_RESULTS):
                    results.append((title, href))

        if not results:
            # Google as fallback
            return google_search(term)

        # Format and return the results
        return format_search_results(term, results)

    except Exception as e:
        return f"Error performing search: {e}"


def google_search(term):
    """
    Search the web using Google as a fallback.

    Args:term (list): Search terms as a list of strings

    """
    search_term = '+'.join(term)
    url = f"https://www.google.com/search?q={search_term}"

    try:
        response = make_http_request(url)

        # Split headers and body
        headers_end = response.find('\r\n\r\n')
        if headers_end == -1:
            return "Invalid HTTP response"

        body = response[headers_end + 4:]

        # Parse the HTML response
        soup = BeautifulSoup(body, 'html.parser')

        # Find search results
        results = []

        # Save raw HTML for debugging
        debug_path = os.path.join(get_cache_path(), "google_search_debug.html")
        with open(debug_path, 'w', encoding='utf-8') as f:
            f.write(body)

        # Method 1: Google's standard result containers
        for result in soup.select('div.g'):
            a_tag = result.select_one('a')
            if not a_tag or not a_tag.has_attr('href'):
                continue

            href = a_tag['href']
            if not href.startswith(('http://', 'https://')):
                continue

            title_elem = result.select_one('h3')
            title = title_elem.get_text().strip() if title_elem else a_tag.get_text().strip()

            if title and href and len(title) > 3 and href not in [r[1] for r in results] and len(
                    results) < MAX_SEARCH_RESULTS:
                results.append((title, href))

        # Method 2: Simplified approach for Google
        if not results:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if (href.startswith(('http://', 'https://')) and
                        'google.com' not in href and
                        not href.startswith('https://webcache.googleusercontent.com')):

                    title = a_tag.get_text().strip() or href
                    if (title and len(title) > 3 and
                            href not in [r[1] for r in results] and
                            len(results) < MAX_SEARCH_RESULTS):
                        results.append((title, href))

        # Format and return the results
        return format_search_results(term, results)

    except Exception as e:
        return f"Error performing search: {e}"


def get_fallback_results():
    return []


def format_search_results(term, results):
    """
    Format search results for display.

    Args:
        term (list): The search terms that were used
        results (list): List of (title, url) tuples

    """
    if not results:
        return f"Search failed for: {' '.join(term)}. No results found."

    output = [f"Search Results for: {' '.join(term)}", ""]

    for i, (title, url) in enumerate(results, 1):
        output.append(f"{i}. {title}")
        output.append(f"   URL: {url}")
        output.append("")

    # Save the results for later access
    save_search_results([url for _, url in results])

    output.append("To access a search result, use: go2web -u <URL> or go2web -u #<result-number>")

    return '\n'.join(output)


def get_cache_path():
    """
    Get the path to the cache directory, creating it if needed.

    """
    cache_dir = os.path.join(os.path.expanduser("~"), ".go2web_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    return cache_dir


def get_cache_key(url):
    """
    Generate a cache key for a URL.

    Returns str: MD5 hash of the URL

    """
    return hashlib.md5(url.encode()).hexdigest()


def is_cache_valid(cache_data):
    """
    Check if cached data is still valid.

    Args:cache_data (dict): The cached data

    """
    return time.time() - cache_data['timestamp'] < CACHE_VALIDITY_SECONDS


def get_from_cache(url):
    """
    Get a response from cache if available and valid.

    """
    cache_path = get_cache_path()
    cache_key = get_cache_key(url)
    cache_file = os.path.join(cache_path, cache_key + ".json")

    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # Check if cache is still valid
            if is_cache_valid(cache_data):
                return cache_data['response']
        except (json.JSONDecodeError, KeyError):
            # Invalid cache file
            pass

    return None


def save_to_cache(url, response):
    """
    Save a response to cache.

    """
    cache_path = get_cache_path()
    cache_key = get_cache_key(url)
    cache_file = os.path.join(cache_path, cache_key + ".json")

    cache_data = {
        'timestamp': time.time(),
        'response': response
    }

    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)


def save_search_results(urls):
    """
    Save search results for later access by number.

    Args:urls (list): List of URLs from search results
    """
    if not urls:
        return

    cache_path = get_cache_path()
    cache_file = os.path.join(cache_path, "last_search_results.json")

    with open(cache_file, 'w') as f:
        json.dump(urls, f)


def get_search_result_url(result_number):
    """
    Get a URL from search results by number.

    Args:result_number (str): The result number with # prefix

    """
    if not result_number.startswith('#'):
        return None

    try:
        index = int(result_number[1:]) - 1
        if index < 0:
            return None

        cache_path = get_cache_path()
        cache_file = os.path.join(cache_path, "last_search_results.json")

        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                urls = json.load(f)

            if not urls or len(urls) == 0:
                print("No search results available. Please perform a search first.")
                return None

            if 0 <= index < len(urls):
                return urls[index]
            else:
                print(f"Search result #{result_number[1:]} is out of range. Available results: 1-{len(urls)}")
        else:
            print("No search results available. Please perform a search first.")
    except (ValueError, IndexError, json.JSONDecodeError) as e:
        print(f"Error accessing search result: {e}")

    return None


def clear_cache_for_search(search_term):
    """
    Clear the cache for a specific search term.

    """
    cache_path = get_cache_path()
    cache_key = get_cache_key(f"search:{search_term}")
    cache_file = os.path.join(cache_path, cache_key + ".json")

    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            print(f"Cache cleared for search: {search_term}")
        except Exception as e:
            print(f"Error clearing cache: {e}")


def main():
    try:
        args = parse_arguments()

        if args.url:
            url = args.url
            # Check if the URL is a search result number
            search_url = get_search_result_url(url)
            if search_url:
                print(f"Accessing search result #{url[1:]}: {search_url}")
                url = search_url
            elif url.startswith('#'):
                # If we got here, get_search_result_url already printed an error message
                return 1

            # Only proceed if we have a valid URL
            if url and not url.startswith('#'):
                cached_response = None if args.force else get_from_cache(url)

                if cached_response:
                    print("(From cache)")
                    print(cached_response)
                else:
                    print(f"Making request to: {url}")
                    response = make_http_request(url)
                    body = parse_http_response(response)
                    save_to_cache(url, body)
                    print(body)
            else:
                return 1

        elif args.search:
            search_term = ' '.join(args.search)
            # Clear cache if force flag is set
            if args.force:
                clear_cache_for_search(search_term)
                cached_results = None
            else:
                cached_results = get_from_cache(f"search:{search_term}")

            if cached_results:
                print("(From cache)")
                print(cached_results)
            else:
                print(f"Searching for: {search_term}")
                results = search(args.search)
                save_to_cache(f"search:{search_term}", results)
                print(results)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
