from scanner import scan_target

result = scan_target("https://example.com")

print("URL:", result["url"])
print("Status Code:", result["status_code"])
print("Server:", result["server"])
print("Cookies:", result["cookies"])