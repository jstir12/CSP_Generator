import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import secrets
from collections import deque

def generate_csp_for_url(url):
    urls_to_visit = deque([url])
    visited_urls = set()
    resource_urls = set()

    while urls_to_visit:
        current_url = urls_to_visit.popleft()
        if current_url in visited_urls:
            continue
        visited_urls.add(current_url)

        try:
            response = requests.get(current_url, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to fetch {current_url}: {e}")
            if response.status_code == 404:
                continue  # Skip URLs that return a 404 error
            continue

        # Handle encoding issues
        response.encoding = response.apparent_encoding
        try:
            soup = BeautifulSoup(response.content, 'html.parser', from_encoding=response.encoding)
        except Exception as e:
            print(f"Failed to parse HTML content from {current_url}: {e}")
            continue

        for tag in soup.find_all(['script', 'img', 'link', 'style', 'font']):
            if tag.name == 'script' and tag.get('src'):
                resource_urls.add(urljoin(current_url, tag['src']))
            elif tag.name == 'img' and tag.get('src'):
                resource_urls.add(urljoin(current_url, tag['src']))
            elif tag.name == 'link' and tag.get('href'):
                resource_urls.add(urljoin(current_url, tag['href']))
            elif tag.name == 'style' and tag.string:
                urls = extract_urls_from_css(tag.string, current_url)
                resource_urls.update(urls)
            elif tag.name == 'font' and tag.get('src'):
                resource_urls.add(urljoin(current_url, tag['src']))

        for script in soup.find_all('script'):
            if script.string:
                urls = extract_urls_from_js(script.string, response)
                resource_urls.update(urls)

        # Find and queue internal links
        for link in soup.find_all('a', href=True):
            link_url = urljoin(current_url, link['href'])
            if is_internal_link(link_url, url) and link_url not in visited_urls:
                urls_to_visit.append(link_url)

    script_sources = ["'self'", "'strict-dynamic'", "'unsafe-inline'"]
    style_sources = ["'self'", "'unsafe-inline'"]
    img_sources = ["'self'", "data:"]
    font_sources = ["'self'"]
    connect_sources = ["'self'"]
    frame_sources = ["'self'"]
    object_sources = ["'none'"]
    require_trusted_types_for = ["'script'"]
    base_uri = ["'self'"]

    for resource_url in resource_urls:
        parsed_url = urlparse(resource_url)
        if parsed_url.scheme in ['http', 'https']:
            netloc = f"{parsed_url.scheme}://*.{parsed_url.netloc}"
            if 'script' in resource_url or 'js' in resource_url:
                script_sources.append(netloc)
            elif 'css' in resource_url:
                style_sources.append(netloc)
            elif 'img' in resource_url:
                img_sources.append(netloc)
            elif 'font' in resource_url or 'woff' in resource_url or 'ttf' in resource_url:
                font_sources.append(netloc)
            elif 'connect' in resource_url or 'api' in resource_url:
                connect_sources.append(netloc)
            elif 'frame' in resource_url or 'embed' in resource_url:
                frame_sources.append(netloc)

    # Generate random nonce value
    nonce = secrets.token_hex(16)
    script_sources.append(f"'nonce-{nonce}'")

    csp_directives = {
        'default-src': ["'self'"],
        'script-src': script_sources,
        'style-src': style_sources,
        'img-src': img_sources,
        'font-src': font_sources,
        'connect-src': connect_sources,
        'frame-src': frame_sources,
        'object-src': object_sources,
        'require-trusted-types-for': require_trusted_types_for,
        'base-uri': base_uri,
    }

    csp_lines = []
    for directive, sources in csp_directives.items():
        formatted_sources = " ".join(sorted(set(sources)))
        csp_lines.append(f"{directive} {formatted_sources}")

    csp = ";\n".join(csp_lines) + ";"
    return csp

def extract_urls_from_js(js_code, response):
    if not js_code:
        return set()
    
    urls = set()
    for match in re.finditer(r'http[s]?://[^\s\'"]+', js_code):
        url = match.group(0)
        urls.add(url)
    return urls

def extract_urls_from_css(css_code, base_url):
    if not css_code:
        return set()
    
    urls = set()
    url_pattern = re.compile(r'url\(([^\)]+)\)')
    matches = re.findall(url_pattern, css_code)
    for match in matches:
        url = match.strip(" '\"")
        urls.add(urljoin(base_url, url))
    return urls

def write_csp_to_file(csp, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(csp)

def get_filename_from_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    
    # Get rid of .com, .org, etc.
    hostname = hostname.split('.')[0]
    path = parsed_url.path.strip('/').replace('/', '_')
    if path:
        filename = f"{hostname}_{path}_csp.txt"
    else:
        filename = f"{hostname}_csp.txt"
    return filename

def is_internal_link(link_url, base_url):
    base_hostname = urlparse(base_url).hostname
    link_hostname = urlparse(link_url).hostname
    return base_hostname == link_hostname

def main():
    url = "https://www.doitbestonline.com/"
    csp = generate_csp_for_url(url)
    if csp:
        filename = get_filename_from_url(url)
        filePath = os.path.join('/Users/jacob/Desktop/Python_CSP_Test/Generated_CSPS', filename)
        write_csp_to_file(csp, filePath)
        print("CSP generated and written to file.")
    else:
        print("Failed to generate CSP.")

if __name__ == "__main__":
    main()
