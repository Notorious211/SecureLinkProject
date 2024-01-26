from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from textblob import TextBlob
from datetime import datetime
import subprocess
import os  
USE_LIVE_API = True  # Change to True for live data, False for dummy data
app = Flask(__name__)
SECURITYTRAILS_API_KEY = 'cjmCx78GlCxHhW42r54kaDWI5kjUrPwG'
SECURITYTRAILS_ENDPOINT = "https://api.securitytrails.com/v1/domain/"
VIRUSTOTAL_API_KEY = '9d62de82929926696edea7189a9a8669e5b435af5943213a7b05d9b68a0d5097'
API_ENDPOINT = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
API_KEY = "at_CggEsI4gvTXDMPkKTjWovyd2XX4UP"
TRUSTPILOT_API_KEY = os.environ.get("TRUSTPILOT_API_KEY")  #API key from the environment variable

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    searched_website = None
    results_dict = {}
    rating = 0
    if request.method == 'POST':
        url = request.form['website']
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        # HTTPS check
        if 'https' in url:
            rating += 10
        else:
            rating -= 5

        

        # Get Domain Info
        domain_info = get_domain_info_api(domain)

        # Check domain age
        if domain_info['age'] != "Unknown" and domain_info['age'] > 365:
            rating += 5
        else:
            rating -= 2

        # Check if registrar is known
        if domain_info['registrar'] != "Unknown":
            rating += 2

        # Check if owner is known
        if domain_info['owner'] != "Unknown":
            rating += 3

        

        domain_info_result = {
            'icon': 'fa-solid fa-info',
            'title': 'Domain Info',
            'description': f"Domain age for {domain}: {domain_info['age']} days.<br>Domain owner for {domain}: {domain_info['owner']}.<br>Registrar: {domain_info['registrar']}.<br>Expiration Date: {domain_info['expiration_date']}"
        }
        results.append(domain_info_result)


        # Web Analysis
        website_analysis = analyze_website(url)
        analysis_info = {
            'icon': 'fa-solid fa-code',
            'title': 'Web Analysis',
            'description': website_analysis
        }
        results.append(analysis_info)

        # Trustpilot Reviews
        trustpilot_reviews = get_trustpilot_reviews(url)
        reviews_info = {
            'icon': 'fa-solid fa-star',
            'title': 'Trustpilot Reviews',
            'description': trustpilot_reviews
        }
        results.append(reviews_info)

        # VirusTotal Analysis
        virustotal_result = get_virustotal_results(url)
        virustotal_info = {
            'icon': 'fa-solid fa-shield-halved',
            'title': 'VirusTotal Analysis',
            'description': f"Detected as malicious by {virustotal_result['malicious_engines']} engines: {', '.join(virustotal_result['malicious_engine_details'])}"
        }
        results.append(virustotal_info)

        # Check for Known Vulnerabilities
        vulnerabilities_info = get_known_vulnerabilities(domain)
        vulnerabilities = {
            'icon': 'fa-solid fa-bug',
            'title': 'Known Vulnerabilities',
            'description': vulnerabilities_info
        }
        results.append(vulnerabilities)

        searched_website = domain
        # Call the SSL check function
        ssl_check_result = check_ssl_certificate(url)
        if ssl_check_result == "SSL certificate is valid!":
            rating += 10
        else:
            rating -= 5

        # Include the SSL check result in the results list
        ssl_info = {
            'icon': 'fa-solid fa-lock',
            'title': 'SSL Check',
            'description': ssl_check_result
        }
        results.append(ssl_info)

        results_dict = {
            'domain_info': domain_info_result,
            'analysis_info': analysis_info,
            'reviews_info': reviews_info,
            'virustotal_info': virustotal_info,
            'vulnerabilities': vulnerabilities,
            'ssl_info': ssl_info, # Include SSL info
            'rating': rating # Include the rating
        }

        searched_website = domain
        results_dict['rating'] = rating

    return render_template("index.html", results=results_dict, searched_website=searched_website)
def analyze_website(url):
    # Web scraping and analysis code
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    output1 = ""

    # Page Title
    output1 += f"<h4>Page Title:</h4><p> {soup.title.string}</p>"

    # Meta tags
    meta_tags = soup.find_all('meta')
    output1 += f"<h4>Meta Tags:</h4><p>Number of meta tags: {len(meta_tags)}</p>"
    output1 += "<p>What are Meta Tags? Meta tags are snippets of text that describe a page's content. They don't appear on the page itself, but only in the page's source code. Meta tags are essentially little content descriptors that help tell search engines what a web page is about. In the context of website legitimacy, well-structured meta tags can indicate a professionally built site, whereas misleading or absent meta tags may be a red flag.</p>"

    # Reviews
    reviews = soup.find_all('div', {'class': 'user-review'})
    if reviews:
        output1 += "<h4>Reviews and Their Sentiments:</h4>"
        for review in reviews:
            review_text = review.text
            blob = TextBlob(review_text)
            sentiment = blob.sentiment
            output1 += f"<p>Review: {review_text}, Sentiment: {sentiment}</p>"
    else:
        output1 += "<h4>Reviews and Their Sentiments:</h4>"
        output1 += "<p>No reviews found.</p>"
        output1 += "<p>Note: The absence of reviews on a website does not necessarily mean it's unsafe. It might simply be a new or less popular website. Always consider multiple factors when evaluating a website's legitimacy.</p>"

    # Images and Alt Text
    images = soup.find_all('img')
    output1 += f"<h4>Images:</h4><p>Number of images: {len(images)}</p>"
    output1 += "<p>Images and their associated alternative text (alt text) can provide insight into a website's authenticity. Well-established and legitimate websites often use high-quality images with appropriate alt text descriptions. The presence of relevant images with accurate alt text can indicate a professionally maintained site, whereas a lack of these or misuse may be a red flag for potential security concerns. Always exercise caution, as images can also be misused for phishing or other malicious intent.</p>"

    # Links Analysis
    links = soup.find_all('a')
    output1 += f"<h4>Links:</h4><p>Number of links: {len(links)}</p>"
    output1 += "<p>The quantity of links on a webpage can offer insights into the site's structure and content strategy. While having many links is not inherently suspicious, an unusually high or low number of links might indicate the quality or nature of the site. Websites designed for user interaction and information sharing typically contain numerous links. However, an abnormal amount of links could be a sign of automated content generation or spammy practices, which might raise security concerns. Assessing this number in the context of the website's purpose and content can contribute to an overall understanding of its legitimacy.</p>"

    output2 = ""

    # HTTPS check
    output2 += "<h4>Does the website Uses HTTPS?</h4>"
    if 'https' in url:
        
        output2 += "<p>The website uses HTTPS.</p>"
        output2 += "<p>What is HTTPS? HTTPS (Hypertext Transfer Protocol Secure) encrypts the data sent and received between your browser and the server, enhancing the security of sensitive information. When a website uses HTTPS, it helps to ensure that any personal or sensitive data is transmitted securely. This is particularly crucial for websites that handle financial transactions, logins, or other personal user data. Always look for 'https://' in the URL to verify a secure connection.</p>"
    else:
        
        output2 += "<p>The website does not use HTTPS.</p>"
        output2 += "<p>Warning: HTTP (Hypertext Transfer Protocol) does not encrypt the data being transmitted between the browser and the server. This could make the information vulnerable to eavesdropping or manipulation by malicious parties. It's advisable to be cautious while entering personal or sensitive information on websites that do not use HTTPS.</p>"
    
    # Sitemap check
    output2 += "<h4>How many Sitemap</h4>"
    sitemap_url = url + '/sitemap.xml'
    response_sitemap = requests.get(sitemap_url)
    if response_sitemap.status_code == 200:
        sitemap_soup = BeautifulSoup(response_sitemap.text, 'xml')

        # Check if it's a sitemap index
        sitemap_indices = sitemap_soup.find_all('sitemap')

        if sitemap_indices:
         num_sitemaps = len(sitemap_indices)
         output2 += f"<p>The website has a sitemap index with {num_sitemaps} sitemaps.</p>"
         output2 += f"<p>The number of sitemaps can give insights into the complexity and structure of the website. A higher number of sitemaps might indicate a larger, more complex site with various sections and content categories. While this number alone doesn't determine the security of a site, it can be an indicator of the website's maturity and the level of effort put into its organization.</p>"
        else:
        # It's not a sitemap index, but a regular sitemap
         output2 += "<p>The website has a single sitemap.</p>"
        output2 += "<p>A single sitemap is common for smaller or less complex sites. It represents a standard approach to site organization and doesn't inherently signal any security concerns.</p>"
    else:
     output2 += "<p>The website does not have a sitemap.</p>"
     output2 += "<p>Note: The absence of a sitemap doesn't necessarily mean the site is unsafe. It may simply reflect a lack of organization or a preference by the site's creators. It is one of many factors to consider when evaluating a website's legitimacy.</p>"

        

    # SSL Check
    output2 += "<h4>Is the SSL Certificate Valid?</h4>"
    ssl_check_result = check_ssl_certificate(url)
    output2 += f"<p>{ssl_check_result}</p>"
    output2 += "<p>An SSL certificate is a digital certificate that authenticates the identity of a website and encrypts information sent to the server using SSL technology. The presence of a valid SSL certificate is a key indicator of a website's trustworthiness and legitimacy. It ensures that any data transmitted between the web server and browser remains encrypted and private. A valid SSL certificate doesn't only mean that the connection is secure; it's also an indication that the owners of the website have undergone a verification process. On the other hand, an invalid or missing SSL certificate could be a red flag for potential security risks. Always be cautious and consider other factors when assessing the overall security of a site.</p>"
    # Favicon
    output1 += "<h4>Does the website have a favicon?</h4>"
    favicon = soup.find('link', rel='icon')
    if favicon:
        output1 += "<p>The website has a favicon, often considered a sign of a professionally designed site.</p>"
    else:
        output1 += "<p>The website does not have a favicon. This doesn't indicate a security concern but might reflect a lack of attention to detail in the site's design.</p>"
    # Robots.txt
    output2 += "<h4>Does the website have a robots.txt file?</h4>"
    robots_url = url + '/robots.txt'
    response_robots = requests.get(robots_url)
    if response_robots.status_code == 200:
     output2 += "<p>The website has a robots.txt file, which can provide insights into the site's SEO practices and content strategy.</p>"
    else:
        output2 += "<p>The website does not have a robots.txt file. This might reflect a lack of SEO optimization, but it's not necessarily a red flag.</p>"
    # Primary Language
    output2 += "<h4>What is the primary language of the website?</h4>"
    lang = soup.html.get('lang')
    if lang:
        output2 += f"<p>The primary language of the website is {lang}.</p>"
    else:
     output2 += "<p>The website does not specify a primary language.</p>"

    # Initialize rating
    rating = 0

    # HTTPS check
    if 'https' in url:
        rating += 10
    else:
        rating -= 5

    # Sitemap check
    if response_sitemap.status_code == 200:
        rating += 5
    else:
        rating -= 2

    # SSL Check
    if ssl_check_result == "Valid":
        rating += 10
    else:
        rating -= 5

    # Favicon check
    if favicon:
        rating += 2

    # Robots.txt check
    if response_robots.status_code == 200:
        rating += 2

    # Meta Tags Check
    if meta_tags:
        rating += 2
    else:
        rating -= 1

    # Images and Alt Text Check
    if images:
        alt_text_present = all(img.has_attr('alt') for img in images)
        if alt_text_present:
            rating += 3
        else:
            rating -= 2
    else:
        rating -= 1

    # Links Analysis
    if links:
        rating += 2
    else:
        rating -= 1

    
    return output1, output2, rating
def get_trustpilot_reviews(url):
    if not USE_LIVE_API:
        return get_dummy_trustpilot_info()
    headers = {
        "Authorization": f"Bearer {TRUSTPILOT_API_KEY}"  # Use the API key in the header
    }
    
    
    endpoint = f"https://api.trustpilot.com/v1/business-units/find?name={url}"
    
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # Extract and return the relevant review data based on Trustpilot
        reviews = data.get("reviews", [])
        return format_trustpilot_reviews(reviews)
    else:
        return "<p>Failed to fetch Trustpilot reviews.</p>"
def format_trustpilot_reviews(reviews):
    
    output = "<h4>Trustpilot Reviews:</h4>"
    for review in reviews:
        # Extract relevant information from each review and format them
        output += f"<p>{review['text']} - Rating: {review['rating']}</p>"
    return output
def check_ssl_certificate(url):
    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        cmd1 = f"echo | openssl s_client -servername {domain} -connect {domain}:443 2>&1"
        output1 = subprocess.check_output(cmd1, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        
        
        cmd2 = "openssl x509 -noout -dates"
        process = subprocess.Popen(cmd2, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output2, error = process.communicate(input=output1.encode("utf-8"))
        
        
        if process.returncode != 0:
            return f"OpenSSL Command Error: {error.decode('utf-8')}"

        not_after_line = [line for line in output2.decode("utf-8").split("\n") if "notAfter" in line][0]
        not_after = not_after_line.split("=")[1].strip()
        expiration_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        
        if datetime.now() > expiration_date:
            return "SSL certificate has expired!"

        return "SSL certificate is valid!"
    except IndexError:
        return "Could not retrieve SSL certificate."
    except Exception as e:
        return f"Error: {e}"
def get_domain_info_api(domain):
    params = {
        "apiKey": API_KEY,
        "domainName": domain,
        "outputFormat": "JSON"
    }

    response = requests.get(API_ENDPOINT, params=params)
    if response.status_code == 200:
        data = response.json()
        age = data.get("WhoisRecord", {}).get("createdDate", "Unknown")
        owner = data.get("WhoisRecord", {}).get("registrant", {}).get("name", "Unknown")
        registrar = data.get("WhoisRecord", {}).get("registrarName", "Unknown")
        expiration_date = data.get("WhoisRecord", {}).get("expiresDate", "Unknown")

        if age != "Unknown":
            creation_date = datetime.strptime(age.split("T")[0], '%Y-%m-%d')
            current_date = datetime.now()
            domain_age = (current_date - creation_date).days
        else:
            domain_age = "Unknown"

        return {
            'age': domain_age,
            'owner': owner,
            'registrar': registrar,
            'expiration_date': expiration_date,
        }
    else:
        return {
            'age': "Failed to fetch domain info",
            'owner': "Failed to fetch domain info",
            'registrar': "Failed to fetch domain info",
            'expiration_date': "Failed to fetch domain info",
        }
def get_virustotal_results(url):
    if not USE_LIVE_API:
        return get_dummy_virustotal_info()
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(endpoint, headers=headers)
    
    print(response.text)
    
    if response.status_code == 200:
        data = response.json()
        last_analysis_results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        malicious_engines = [engine for engine, result in last_analysis_results.items() if result.get("category") == "malicious"]
        return {'malicious_engines': len(malicious_engines), 'malicious_engine_details': malicious_engines}
    else:
        return {'malicious_engines': 0, 'malicious_engine_details': [f"Failed to fetch VirusTotal results. Status Code: {response.status_code}"]}
def get_known_vulnerabilities(domain):
    if not USE_LIVE_API:
        return get_dummy_known_vulnerabilities()
    headers = {
        "APIKEY": SECURITYTRAILS_API_KEY
    }
    response = requests.get(SECURITYTRAILS_ENDPOINT + domain + "/subdomains", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = data.get("subdomains", [])
        formatted_vulnerabilities = ""  # This will store the formatted vulnerability data

        for sub in subdomains:
            response_vuln = requests.get(SECURITYTRAILS_ENDPOINT + f"{sub}.{domain}/vulnerabilities", headers=headers)
            if response_vuln.status_code == 200:
                vuln_data = response_vuln.json()
                sub_vulns = vuln_data.get('vulnerabilities', [])
                if sub_vulns:
                    formatted_vulnerabilities += f"<h5>Subdomain: {sub}.{domain}</h5>"
                    for vuln in sub_vulns:
                        formatted_vulnerabilities += f"<p>Vulnerability: {vuln.get('name', 'N/A')} - Description: {vuln.get('description', 'N/A')}</p>"

        return formatted_vulnerabilities if formatted_vulnerabilities else "No vulnerabilities found."
    else:
        return "<p>Failed to fetch vulnerabilities info.</p>"  
#The dummy data is just for me to code the css instad of refreshing and calling each time the APIs(the number of request is limited) i used a dummy data,USE_LIVE_API = True (set it to false to activate it)     
def get_dummy_trustpilot_info():
    dummy_reviews = [
    {
        'text': "Amazing service and fast shipping!",
        'rating': 5
    },
    {
        'text': "Had some issues with the product but their support team helped me right away.",
        'rating': 4
    },
    {
        'text': "Terrible experience. I would never shop here again.",
        'rating': 1
    }
]

    formatted_reviews = format_trustpilot_reviews(dummy_reviews)
    return formatted_reviews
def get_dummy_domain_info():
    age = "999999"  # or some dummy value
    owner = "GGGGGGG"  # or some dummy value
    return age, owner
def get_dummy_virustotal_info():
    malicious_engines_count = 3  # or any other dummy value for the count of malicious engines
    malicious_engines = ["Engine1", "Engine2", "Engine3"]  # or any other dummy values for malicious engines
    return malicious_engines_count, malicious_engines
def get_dummy_known_vulnerabilities():
    # Create dummy vulnerabilities data
    formatted_vulnerabilities = "<h5>Subdomain: dummy.example.com</h5>"
    formatted_vulnerabilities += "<p>Vulnerability: DummyVuln1 - Description: This is a dummy vulnerability</p>"
    formatted_vulnerabilities += "<p>Vulnerability: DummyVuln2 - Description: This is another dummy vulnerability</p>"
    return formatted_vulnerabilities

if __name__ == "__main__":
    #in Azure
    if 'AZURE_RUN_ENVIRONMENT' in os.environ:
        app.run()
    else:
        app.run(host="127.0.0.1", port=8080, debug=True)
