from crawler import crawl


target = "https://juice-shop.herokuapp.com/"

pages = crawl(
    target,
    max_pages=20
)

print("\nDiscovered Pages:")

for page in pages:
    print(page)