import requests
import bs4


def scan_web_app(url):
    # Send a GET request to the URL
    res = requests.get(url)

    # Check for vulnerabilities
    vuln_list = []
    if res.status_code != 200:
        vuln_list.append("Unsuccessful HTTP request")
    if "X-Frame-Options" not in res.headers:
        vuln_list.append("Clickjacking")
    if "Content-Security-Policy" not in res.headers:
        vuln_list.append("Content injection")

    # Parse the HTML
    soup = bs4.BeautifulSoup(res.text, "html.parser")

    # Check for insecure forms
    forms = soup.find_all("form")
    for form in forms:
        if form.get("method") != "post":
            vuln_list.append("Insecure form method")
        if not form.get("action").startswith("https://"):
            vuln_list.append("Insecure form action")

    # Return the list of vulnerabilities
    return vuln_list


# Test the web app scanner
url = "https://www.example.com"
vulnerabilities = scan_web_app(url)
print(f"Vulnerabilities found on {url}:")
print(vulnerabilities)
