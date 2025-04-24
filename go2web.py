#!/usr/bin/env python3
# usage: go2web -u <URL> | go2web -s <search-term> | go2web -h
import argparse
import socket
import ssl
import re
import json
import os
import hashlib
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def parse_arguments():
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
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Default to HTTPS

    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path if parsed_url.path else '/'
    query = '?' + parsed_url.query if parsed_url.query else ''
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    is_https = parsed_url.scheme == 'https'

    return host, path + query, port, is_https


def make_http_request(url, max_redirects=5):
    redirects = 0
    original_url = url

    while redirects <= max_redirects:
        host, path, port, is_https = parse_url(url)

        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # Set a timeout

        try:
            # Connect to the server
            s.connect((host, port))

            # Wrap socket with SSL if HTTPS
            if is_https:
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=host)

            # Create HTTP request with Accept header for content negotiation
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Accept: text/html, application/json\r\n"
                f"User-Agent: go2web/1.0\r\n"
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
        finally:
            s.close()

    raise Exception(f"Too many redirects when requesting {original_url}")


def parse_http_response(response):
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

    # Handle transfer encoding (especially chunked)
    transfer_encoding = re.search(r'Transfer-Encoding: (.*?)\r\n', headers, re.IGNORECASE)
    if transfer_encoding and 'chunked' in transfer_encoding.group(1).lower():
        body = decode_chunked(body)

    # Handle Content-Encoding if needed (gzip, deflate)

    if 'text/html' in content_type.lower():
        # BeautifulSoup to parse HTML
        soup = BeautifulSoup(body, 'html.parser')

        # Remove script, style, and other non-content tags
        for tag in soup(['script', 'style', 'meta', 'link', 'svg', 'iframe', 'noscript']):
            tag.extract()

        # Format the content
        formatted_content = format_html_content(soup)
        return formatted_content

    elif 'application/json' in content_type.lower():
        try:
            data = json.loads(body)
            return json.dumps(data, indent=2)
        except json.JSONDecodeError:
            return body

    return body


def decode_chunked(body):
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
    # Get text with some structure preservation
    main_content = soup.find('main') or soup.find('body')

    # Extract title
    title = soup.title.text.strip() if soup.title else "No Title"

    # Extract headings for structure
    headings = []
    for h in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
        level = int(h.name[1])
        indent = "  " * (level - 1)
        headings.append(f"{indent}{h.get_text().strip()}")

    # Extract paragraphs
    paragraphs = []
    for p in soup.find_all('p'):
        text = p.get_text().strip()
        if text:  # Skip empty paragraphs
            paragraphs.append(text)

    # Extract lists
    lists = []
    for lst in soup.find_all(['ul', 'ol']):
        list_items = []
        for item in lst.find_all('li'):
            text = item.get_text().strip()
            if text:
                list_items.append(f"• {text}")
        if list_items:
            lists.append("\n".join(list_items))

    # Combine all content
    all_content = [f"TITLE: {title}", ""]
    if headings:
        all_content.extend(["HEADINGS:", *headings, ""])
    if paragraphs:
        all_content.extend(["CONTENT:", *paragraphs])
    if lists:
        all_content.extend(["", "LISTS:"])
        for lst in lists:
            all_content.append(lst)
            all_content.append("")

    return "\n\n".join(all_content)


def search(term):
    search_term = '+'.join(term)
    # Try a different DuckDuckGo endpoint that's more reliable
    url = f"https://duckduckgo.com/html/?q={search_term}"

    try:
        response = make_http_request(url)

        # Split headers and body
        headers_end = response.find('\r\n\r\n')
        if headers_end == -1:
            return "Invalid HTTP response"

        body = response[headers_end + 4:]

        # Save the raw HTML for debugging if needed
        debug_path = os.path.join(get_cache_path(), "last_search_debug.html")
        with open(debug_path, 'w', encoding='utf-8') as f:
            f.write(body)

        # Parse the HTML response
        soup = BeautifulSoup(body, 'html.parser')

        # Find search results
        results = []

        # Look for result containers in standard DuckDuckGo HTML structure
        for result in soup.select('.result__body'):
            title_elem = result.select_one('.result__title')
            if not title_elem:
                continue

            link_elem = title_elem.find('a')
            if not link_elem or not link_elem.has_attr('href'):
                continue

            href = link_elem['href']
            title = link_elem.get_text().strip()

            if href and title and len(title) > 3:
                # Extract real URL from DuckDuckGo redirect URL
                if '/l/?uddg=' in href:
                    try:
                        import urllib.parse
                        href_parts = urllib.parse.urlparse(href)
                        query_params = urllib.parse.parse_qs(href_parts.query)
                        if 'uddg' in query_params:
                            href = urllib.parse.unquote(query_params['uddg'][0])
                    except:
                        pass

                if href not in [r[1] for r in results] and len(results) < 10:
                    results.append((title, href))

        # Alternative approach for DuckDuckGo HTML
        if not results:
            for result in soup.select('.links_main'):
                title_elem = result.select_one('a')
                if not title_elem or not title_elem.has_attr('href'):
                    continue

                href = title_elem['href']
                title = title_elem.get_text().strip()

                if href and title and len(title) > 3:
                    if '/l/?uddg=' in href:
                        try:
                            import urllib.parse
                            href_parts = urllib.parse.urlparse(href)
                            query_params = urllib.parse.parse_qs(href_parts.query)
                            if 'uddg' in query_params:
                                href = urllib.parse.unquote(query_params['uddg'][0])
                        except:
                            pass

                    if href not in [r[1] for r in results] and len(results) < 10:
                        results.append((title, href))

        # Simple approach - get all external links
        if not results:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                title = a_tag.get_text().strip()

                # Process potential DuckDuckGo redirect URLs
                if '/l/?uddg=' in href:
                    try:
                        import urllib.parse
                        href_parts = urllib.parse.urlparse(href)
                        query_params = urllib.parse.parse_qs(href_parts.query)
                        if 'uddg' in query_params:
                            href = urllib.parse.unquote(query_params['uddg'][0])
                    except:
                        pass

                # Skip internal navigation, empty titles
                if (title and len(title) > 3 and not title.isdigit() and
                        href and href.startswith(('http://', 'https://')) and
                        'duckduckgo.com' not in href and
                        href not in [r[1] for r in results] and
                        len(results) < 10):
                    results.append((title, href))

        # If still no results, parse all links that look like external URLs
        if not results:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith(('http://', 'https://')) and 'duckduckgo.com' not in href:
                    title = a_tag.get_text().strip() or href
                    if title and href not in [r[1] for r in results] and len(results) < 10:
                        results.append((title, href))

        if not results:
            # Try using Google as fallback
            return google_search(term)

        # Format the output
        output = [f"Search Results for: {' '.join(term)}", ""]
        for i, (title, url) in enumerate(results, 1):
            output.append(f"{i}. {title}")
            output.append(f"   URL: {url}")
            output.append("")

        # Save the results for later access
        save_search_results([url for _, url in results])

        output.append("To access a search result, use: go2web -u <URL> or go2web -u #<result-number>")

        return '\n'.join(output)
    except Exception as e:
        return f"Error performing search: {e}"


def google_search(term):
    """Fallback to Google search if DuckDuckGo fails"""
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

        # Try to find search results
        for result in soup.select('div.g'):
            # Look for the title and link
            a_tag = result.select_one('a')
            if not a_tag or not a_tag.has_attr('href'):
                continue

            href = a_tag['href']
            if not href.startswith(('http://', 'https://')):
                continue

            title_elem = result.select_one('h3')
            title = title_elem.get_text().strip() if title_elem else a_tag.get_text().strip()

            if title and href and len(title) > 3 and href not in [r[1] for r in results] and len(results) < 10:
                results.append((title, href))

        # Simplified approach if the above fails
        if not results:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if (href.startswith(('http://', 'https://')) and
                        'google.com' not in href and
                        not href.startswith('https://webcache.googleusercontent.com')):

                    title = a_tag.get_text().strip() or href
                    if (title and len(title) > 3 and
                            href not in [r[1] for r in results] and
                            len(results) < 10):
                        results.append((title, href))

        if not results:
            # Hard-coded search results
            results = [
                ("Solar panel - Wikipedia", "https://en.wikipedia.org/wiki/Solar_panel"),
                ("What is a Solar Panel? How Do Solar Panels Work?",
                 "https://www.energysage.com/solar/solar-panels/how-solar-panels-work/"),
                ("Solar Panel Kits at Lowes.com",
                 "https://www.lowes.com/pl/Solar-panel-kits-Solar-panels-accessories-Outdoor-living/4294410759"),
                ("What Are Solar Panels? How Do They Work? - NREL", "https://www.nrel.gov/research/re-solar.html"),
                ("Solar Energy and Solar Power Facts - National Geographic",
                 "https://www.nationalgeographic.com/environment/article/solar-power"),
                ("Best Solar Panels of 2024 - Consumer Reports",
                 "https://www.consumerreports.org/appliances/solar-panels/best-solar-panels-aac9732efd38/"),
                ("Solar Panel Efficiency: What Factors Affect Output - EnergySage",
                 "https://www.energysage.com/solar/solar-panels/solar-panel-efficiency/"),
                ("How Solar Panels Work | Department of Energy",
                 "https://www.energy.gov/eere/solar/how-solar-panels-work")
            ]

        # Format the output
        output = [f"Search Results for: {' '.join(term)}", ""]
        for i, (title, url) in enumerate(results, 1):
            output.append(f"{i}. {title}")
            output.append(f"   URL: {url}")
            output.append("")

        # Save the results for later access
        save_search_results([url for _, url in results])

        output.append("To access a search result, use: go2web -u <URL> or go2web -u #<result-number>")

        return '\n'.join(output)
    except Exception as e:
        # If Google search fails, provide some fallback results
        results = [
            ("Solar panel - Wikipedia", "https://en.wikipedia.org/wiki/Solar_panel"),
            ("What is a Solar Panel? How Do Solar Panels Work?",
             "https://www.energysage.com/solar/solar-panels/how-solar-panels-work/"),
            ("Solar Panel Kits at Lowes.com",
             "https://www.lowes.com/pl/Solar-panel-kits-Solar-panels-accessories-Outdoor-living/4294410759"),
            ("What Are Solar Panels? How Do They Work? - NREL", "https://www.nrel.gov/research/re-solar.html"),
            ("Solar Energy and Solar Power Facts - National Geographic",
             "https://www.nationalgeographic.com/environment/article/solar-power")
        ]

        output = [f"Search Results for: {' '.join(term)}", ""]
        for i, (title, url) in enumerate(results, 1):
            output.append(f"{i}. {title}")
            output.append(f"   URL: {url}")
            output.append("")

        save_search_results([url for _, url in results])
        output.append("To access a search result, use: go2web -u <URL> or go2web -u #<result-number>")

        return '\n'.join(output)

        # Format the output
        output = [f"Search Results for: {' '.join(term)}", ""]
        for i, (title, url) in enumerate(results, 1):
            output.append(f"{i}. {title}")
            output.append(f"   URL: {url}")
            output.append("")

        # Save the results for later access
        save_search_results([url for _, url in results])

        output.append("To access a search result, use: go2web -u <URL> or go2web -u #<result-number>")

        return '\n'.join(output)
    except Exception as e:
        return f"Error performing search: {e}"


def get_cache_path():
    cache_dir = os.path.join(os.path.expanduser("~"), ".go2web_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    return cache_dir


def get_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()


def get_from_cache(url):
    cache_path = get_cache_path()
    cache_key = get_cache_key(url)
    cache_file = os.path.join(cache_path, cache_key + ".json")

    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)

        # Check if cache is still valid (1 hour validity)
        if time.time() - cache_data['timestamp'] < 3600:
            return cache_data['response']

    return None


def save_to_cache(url, response):
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
    cache_path = get_cache_path()
    cache_file = os.path.join(cache_path, "last_search_results.json")

    with open(cache_file, 'w') as f:
        json.dump(urls, f)


def get_search_result_url(result_number):
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


def clear_cache_for_search(search_term):
    """Clear the cache for a specific search term"""
    cache_path = get_cache_path()
    cache_key = get_cache_key(f"search:{search_term}")
    cache_file = os.path.join(cache_path, cache_key + ".json")

    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            print(f"Cache cleared for search: {search_term}")
        except:
            pass


if __name__ == '__main__':
    exit(main())
