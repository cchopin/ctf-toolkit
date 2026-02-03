import re

import requests
from bs4 import BeautifulSoup

PAGE_URL = "http://94.237.120.112:45175"


def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(
            f"HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting..."
        )
        exit(1)

    return resp.content.decode()


html = get_html_of(PAGE_URL)
soup = BeautifulSoup(html, "html.parser")
raw_text = soup.get_text()
all_words = re.findall(r"\w+", raw_text)

word_count = {}

for word in all_words:
    if len(word) <= 8:
        continue
    current_count = word_count.get(word, 0)
    word_count[word] = current_count + 1

top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)

for i in range(10):
    print(top_words[i][0])
