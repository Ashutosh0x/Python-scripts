zimport requests
from colorama import Fore, Style

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Define function to format text
def format_text(title, item):
    cr = '\r\n'
    section_break = cr + "*" * 30 + cr
    item = str(item)
    text = f"{Style.BRIGHT}{Fore.RED}{title}{Fore.RESET}{section_break}{item}{section_break}"
    return text

try:
    # Make the request to example.com
    r = requests.get('https://www.example.com', verify=False)

    # Check if the request was successful
    if r.status_code == 200:
        # Print formatted output
        print(format_text('Status Code:', r.status_code))
        print(format_text('Headers:', r.headers))
        print(format_text('Cookies:', r.cookies))
        print(format_text('Text:', r.text))
    else:
        print("Request was not successful. Status code:", r.status_code)

except requests.exceptions.RequestException as e:
    # Handle exceptions
    print("Error making request:", e)
