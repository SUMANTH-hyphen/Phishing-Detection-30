import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
from ipwhois import IPWhois

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
        except:
            pass


        

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


     # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.IPv4Address(self.domain)
            return -1
        except ipaddress.AddressValueError:
            try:
                # If it fails, try to convert the components of a hexadecimal IP to integers
                hex_components = self.domain.split('.')
                decimal_components = [int(x, 16) for x in hex_components]
                # Create a dotted-decimal IP address
                dotted_decimal_ip = ".".join(map(str, decimal_components))
                # Validate the dotted-decimal IP address
                ipaddress.IPv4Address(dotted_decimal_ip)
                return -1
            except (ValueError, ipaddress.AddressValueError):
                return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = self.url.count(".")
        print(dot_count)
        if dot_count == 2 or dot_count == 3:
            return 1
        elif dot_count > 2 and dot_count < 4 or dot_count == 1:
            return 0
        else:
            return -1

    # 8.HTTPS
    def Https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https and 'https' not in self.domain and 'http' not in self.domain:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            # gethostbyname() requires only domain name as arg.
            # whois_info = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
            creation_date = self.whois_response["asn_date"]
            try:
                # Convert the creation_date string to a datetime object
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                
                # Get the current date
                current_date = datetime.now()
                
                # Calculate the age
                age = current_date.year - creation_date.year - ((current_date.month, current_date.day) < (creation_date.month, creation_date.day))
                details = self.whois_response["nets"][0]
                if details["emails"] is None:
                    return -1
                elif age >= 1 and details["description"] and details["address"] and details["postal_code"] and len(details["emails"]):
                    return 1
                else:
                    return -1
            except:
                -1
        except Exception as error:
            print(error)
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    def RequestURL(self):
        try:
            success = 0
            i = 0

            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    if self.urlparse.netloc in urlparse(element['src']).netloc or len(urlparse(element['src']).netloc.split('.')) == 1:
                        success += 1
                    i += 1

            # Calculate the percentage
            if i > 0:
                percentage = (success / i) * 100
                if percentage < 22.0 or percentage == 100.0:
                    print("(re) legitimate", percentage)
                    return 1  # Legitimate
                elif 22.0 <= percentage < 61.0:
                    print("(re) suspicious", percentage)
                    return 0  # Suspicious
                else:
                    print("(re) phishing", percentage)
                    return -1  # Phishing
            else:
                print("(re) No objects found")
                return 0  # Phishing if no objects found
        except ZeroDivisionError:
            print("(re) Division by zero")
            return 0
        except Exception as e:
            print(f"(re) An error occurred: {e}")
            return -1  # Phishing if an error occurs
    
    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                # Check if href attribute exists and is not empty
                if 'href' in a.attrs and a['href']:
                    href_lower = a['href'].lower()
                    # Check for unsafe anchor links
                    if "#" in href_lower or "javascript" in href_lower or "mailto" in href_lower or not (self.url in href_lower or self.domain in href_lower) :
                        if not re.match('^/.*$', href_lower):
                            unsafe += 1
                    i += 1
            # Calculate percentage and classify based on rules
            if i > 0:
                percentage = (unsafe / i) * 100
                if percentage < 31.0:
                    return 1  # Legitimate
                elif 31.0 <= percentage < 67.0:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing
            else:
                return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
        
            for link in self.soup.find_all('link', href=True):
                if self.urlparse.netloc in link['href'] or len(urlparse(link['href']).netloc.split('.')) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all('script', src=True):
                if self.urlparse.netloc in script['src'] or len(urlparse(script['src']).netloc.split('.')) == 1:
                    success += 1
                i += 1

            # Check if no tags were found
            if i == 0:
                print("(li) No <link> or <script> tags found")
                return 0

            # Calculate percentage
            try:
                percentage = (success / i) * 100
                if percentage < 17.0:
                    print("(li) legitimate", percentage)
                    return 1
                elif 17.0 <= percentage < 81.0:
                    print("(li) not able to tell", percentage)
                    return 0
                else:
                    print("(li) phishing", percentage)
                    return -1
            except ZeroDivisionError:
                print("(li) Division by zero")
                return 0
        except Exception as e:
            print(f"(li) An error occurred: {e}")
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
             return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            # gethostbyname() requires only domain name as arg.
            # whois_info = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
            creation_date = self.whois_response["asn_date"]
            try:
                # Convert the creation_date string to a datetime object
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                
                # Get the current date
                current_date = datetime.now()
                
                # Calculate the age
                age = current_date.year - creation_date.year - ((current_date.month, current_date.day) < (creation_date.month, creation_date.day))
                details = self.whois_response["nets"][0]
                if details["emails"] is None:
                    return -1
                elif age >= 1 and details["description"] and details["address"] and details["postal_code"] and len(details["emails"]):
                    return 1
                else:
                    return -1
            except:
                -1
        except Exception as error:
            print(error)
            return -1

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            # gethostbyname() requires only domain name as arg.
            # whois_info = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
            creation_date = self.whois_response["asn_date"]
            try:
                # Convert the creation_date string to a datetime object
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                
                # Get the current date
                current_date = datetime.now()
                
                # Calculate the age
                age = current_date.year - creation_date.year - ((current_date.month, current_date.day) < (creation_date.month, creation_date.day))
                details = self.whois_response["nets"][0]
                if details["emails"] is None:
                    return -1
                elif age >= 1 and details["description"] and details["address"] and details["postal_code"] and len(details["emails"]):
                    return 1
                else:
                    return -1
            except:
                -1
        except Exception as error:
            print(error)
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            api_key = "e019ecc4937f4135bb51e6e07582fc9b"
            # Extract domain from URL
            domain = self.url.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
            # Construct API URL
            api_url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
            
            # Make the API request
            response = requests.get(api_url)
            
            # Check if request was successful
            if response.status_code == 200:
                data = response.json()
                rank = data.get('similar_rank', {}).get('rank')
                if rank is not None:
                    if rank < 100000:
                        print("Success")
                        print("1")
                        return 1
                    else:
                        return 0
                else:
                    print("Rank data not found in response")
                    return -1
            else:
                # Request was not successful
                print("API Error:", response.text)  # Print error message
                return -1
        except Exception as e:
            # Handle any exceptions
            print("Error:", e)
            return -1

    # 27. PageRank
    def PageRank(self):
        api_url = "https://openpagerank.com/api/v1.0/getPageRank"
        api_key = "c0wwsso8s8g4g80cwwg4co8c8w88wwgk0gswkg48"
        threshold = 3  # Example threshold value
        try:
            # Make the API request
            params = {'domains[]': self.url}
            headers = {'API-OPR': api_key}
            response = requests.get(api_url, params=params, headers=headers)
            
            # Process API response
            data = response.json()
            if 'response' in data and len(data['response']) > 0:
                page_rank = float(data['response'][0]['page_rank_decimal'])  # Convert to float
                print(page_rank)
                if page_rank > threshold:
                    print("pagerank(legi)", page_rank)
                    return 1
                else:
                    print("pagerank(phis)", page_rank)
                    return -1  
            else:
                return -1
        except Exception as e:
            print("Error fetching page rank:", e)
            return -1
            

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            # Fetch search results page directly
            search_url = f"https://www.google.com/search?q={self.url}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(search_url, headers=headers)
            response.raise_for_status()

            # Check if the URL appears in the search results
            if self.url in response.text:
                print("GI legitimate")
                return 1  # Legitimate
            else:
                print("Phishing")
                return -1  # Phishing
        except Exception as e:
            print("Error during Google Index check:", e)
            return -1  # Phishing

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            external_links = [link.get('href') for link in self.soup.find_all('a') if link.get('href') and not urlparse(link.get('href')).netloc.endswith(self.domain)]
            external_links_count = len(external_links)
            if external_links_count == 0:
                return -1
            elif external_links_count > 0 and external_links_count <= 2:
                return 0
            else:
                return 1
        except :
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        return self.features
