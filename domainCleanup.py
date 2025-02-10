import csv
import argparse
import dns.resolver
import re
import whois
import nmap

def main():
    #Allow for cmdline arguments to be passed
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help = "Provide input file name")
    parser.add_argument('-o', '--Output', help = "Provide an output file name", default="DomainCleanUpOutput.csv")
    parser.add_argument('-p', '--Ports', help = "Provide specified ports to include in scan (Ex: 1,2,3)", default="22,80,81,443,8080,8443,9443")
    parser.add_argument('-r', '--Resolver', help = "Specify DNS Resolver (Ex: 8.8.8.8)", default='8.8.8.8')
    args = parser.parse_args()
    inputFile = args.filename

    ports = [int(x) for x in args.Ports.split(',')]

    domainDict = parseFile(inputFile)
    domainDict = checkAll(domainDict, ports, args.Resolver)

    outputFile(domainDict, args.Output, ports)
    print(f"\n\n\n*****************************************************\nScan Results:\nPorts Scanned: {ports}\nDNS Resolver: {args.Resolver}\nResults have been written to {args.Output}\n*****************************************************")

def parseFile(inputFile):
    #Method takes in an input file and tries to open it with a csv reader, then it takes the first column
    #of inputs (excluding the header), and returns a list of entries-- in this case, the domains.

    #Read input file
    domainDict = {}
    try: 
        with open(inputFile, 'r') as file:
            csvReader = csv.reader(file)
            #skip header row, (go next row)
            next(csvReader)
            for row in csvReader:
                #Add domain names to collection, with empty list to store later data
                domainDict[row[0]] = []
    except: 
        print("An error has occured. Check your input file and try again.")

    return domainDict

def checkDNS(domain, resolverIP):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolverIP]
    try:
        answers = resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return ["NoAnswer"]
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except Exception as e:
        return [f"Error: {str(e)}"]

def checkAll(domainDict, ports, resolverIP):
    counter = 0
    total = len(domainDict.keys())
    for domain in domainDict.keys():
        counter += 1
        #sanitizedDomain = sanitizeDomain(domain)
        print(f"Processesing Domain #{counter}/{total} ({domain})")
        portResults = scanPorts(domain, ports)
        DNSresults = checkDNS(domain, resolverIP)
        WHOISresult = checkWHOIS(domain)
        domainDict[domain] = [DNSresults, WHOISresult, portResults]
    return domainDict

def checkWHOIS(domain):
    try:
        domainInfo = whois.whois(domain)
        return domainInfo
    except Exception as e:
        return f"WHOIS Error: {str(e)}"

def sanitizeDomain(domain):
    #rm http://, https://, and www.
    domain = re.sub(r'^(https?://)?(www\.)?', '', domain.lower())
    #rm trailing slash and everything after it
    domain = re.sub(r'/.*$', '', domain)
    #rm trailing period
    domain = domain.rstrip('.')
    return domain.strip()

def scanPorts(domain, ports):
    nm = nmap.PortScanner()
    portStr = listToString(ports)
    try: 
        result = nm.scan(domain, portStr)
        ip = nm.all_hosts()[0]
        return result['scan'][ip]['tcp']
    except Exception as e:
        #print(f"Exception has occured when scanning {domain}: {str(e)}")
        return {"Error": f"{str(e)}"}
    
def listToString(intList):
    return ','.join(map(str, intList))

def outputFile(domainDict, outputFile, ports):
    with open(outputFile, 'w', newline='') as csvfile:
        portHeaders = [f"Port {x}" for x in ports]
        fieldnames = ['Domain', 'A Records', 'WHOIS Creation Date', 'WHOIS Last Modified', 'WHOIS Expiration Date'] + portHeaders
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for domain, data in domainDict.items():
            dnsData, whoisData, portData = data
            row = {
                'Domain': domain,
                'A Records': ', '.join(dnsData),
                'WHOIS Creation Date': getattr(whoisData, 'creation_date', 'N/A') if isinstance(whoisData, whois.parser.WhoisEntry) else 'N/A',
                'WHOIS Last Modified': getattr(whoisData, 'last_updated', 'N/A') if isinstance(whoisData, whois.parser.WhoisEntry) else 'N/A',
                'WHOIS Expiration Date': getattr(whoisData, 'expiration_date', 'N/A') if isinstance(whoisData, whois.parser.WhoisEntry) else 'N/A',
            }
            if not row['WHOIS Creation Date'] or row['WHOIS Creation Date'] == "":
                row['WHOIS Creation Date'] = "N/A"
            if not row['WHOIS Last Modified'] or row['WHOIS Last Modified'] == "":
                row['WHOIS Last Modified'] = "N/A"
            if not row['WHOIS Expiration Date'] or row['WHOIS Expiration Date'] == "":
                row['WHOIS Expiration Date'] = "N/A"

            for port in ports:
                if port in portData:
                    portInfo = portData[port]
                    row[f'Port {port}'] = f"{portInfo['state']} - {portInfo['name']} - {portInfo['product']} {portInfo['version']}".strip()
                else:
                    row[f'Port {port}'] = 'N/A'

            writer.writerow(row)

main()