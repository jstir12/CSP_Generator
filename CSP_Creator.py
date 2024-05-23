import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import secrets

def generate_csp_for_url(url):
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to fetch the website content.")
        return None

    soup = BeautifulSoup(response.content, 'html.parser')

    resource_urls = set()

    # Find all script, link, img, style, and font tags
    for tag in soup.find_all(['script', 'img', 'link', 'style', 'font']):
        if tag.name == 'script' and tag.get('src'):
            resource_urls.add(tag['src'])
        elif tag.name == 'link' and tag.get('href'):
            resource_urls.add(tag['href'])
        elif tag.name == 'img' and tag.get('src'):
            resource_urls.add(tag['src'])
        elif tag.name == 'style' and tag.string:
            urls = extract_urls_from_css(tag.string)
            resource_urls.update(urls)
        elif tag.name == 'font' and tag.get('src'):
            resource_urls.add(tag['src'])

    # Extract URLs from inline JavaScript
    for script in soup.find_all('script'):
        if script.string:
            urls = extract_urls_from_js(script.string, response)
            resource_urls.update(urls)


    script_sources = ["'self'", "'strict-dynamic'", "'unsafe-inline'"]  # Add 'unsafe-inline'
    style_sources = ["'self'", "'unsafe-inline'"]
    img_sources = ["'self'", "data:"]
    font_sources = ["'self'"]
    connect_sources = ["'self'"]
    frame_sources = ["'self'"]
    object_sources = ["'none'"]
    require_trusted_types_for = ["'script'"]
    base_uri = ["'self'"]

    for url in resource_urls:
        parsed_url = urlparse(url)
        if parsed_url.scheme in ['http', 'https']:
            # Use wildcard for subdomains
            netloc = f"{parsed_url.scheme}://*.{parsed_url.netloc}"
            if 'script' in url or 'js' in url:
                script_sources.append(netloc)
            elif 'css' in url:
                style_sources.append(netloc)
            elif 'img' in url:
                img_sources.append(netloc)
            elif 'font' in url or 'woff' in url or 'ttf' in url:
                font_sources.append(netloc)
            elif 'connect' in url or 'api' in url:
                connect_sources.append(netloc)
            elif 'frame' in url or 'embed' in url:
                frame_sources.append(netloc)

    # Generate a random nonce value
    nonce = secrets.token_hex(16)
    script_sources.append(f"'nonce-{nonce}'")  # Add nonce to script-src

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
    # Leverage urllib.parse for URL parsing within JavaScript code
    for match in re.finditer(r'[^\s\'"]+', js_code):  # Simplified regex pattern
        url = match.group(0)
        if not url:
            continue

        # Check for valid URL schemes (http or https) before adding
        if url.startswith(('http://', 'https://')):
            urls.add(url)
        else:
            # Handle relative URLs (optional)
            # You can uncomment and modify this section to handle relative URLs based on the context of the script
            parsed_url = urlparse(response.url)  # Assuming response object is available
            urls.add(urljoin(url, parsed_url.geturl()))

    return urls


def extract_urls_from_css(css_code):
    if not css_code:
        return set()

    urls = set()
    # Regex to find URLs in CSS code (unchanged)
    url_pattern = re.compile(r'url\(([^\)]+)\)')
    matches = re.findall(url_pattern, css_code)
    for match in matches:
        url = match.strip(" '")
        urls.add(url)
    return urls

def write_csp_to_file(csp, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as file:
        file.write(csp)

# Example usage:
website_url = "https://kidszoo.org/"
generated_csp = generate_csp_for_url(website_url)
if generated_csp:
    print("Generated CSP:")
    print(generated_csp)
    file_path = '/Users/jacob/Desktop/Python_CSP_Test/generated_csp.txt'
    write_csp_to_file(generated_csp, file_path)
else:
    print("Failed to generate CSP.")
