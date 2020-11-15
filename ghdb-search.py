import requests
import re
import argparse
from argparse import RawTextHelpFormatter
import sys


def main():
	#default values
	output_file = "dorks.txt"
	params = {
		"page_start" : "0",
		"page_finish" : "",
		"search" : "",
		"search_regix" : "false",
		"category_no" : ""
	}

	description =  (
		"Example: python get_dorks.py -s 'mysql' -c 1 -n 3 -ps 1 -o dorks.txt\n"
		+"\nCategory numbers:\n"
		+"	1.   Footholds\n"
		+"	2.   Files Containing Usernames\n"
		+"	3.   Sensitive Directories\n"
		+"	4.   Web Server Detection\n"
		+"	5.   Vulnerable Files\n"
		+"	6.   Vulnerable Servers\n"
		+"	7.   Error Messages\n"
		+"	8.   Files Containing Juicy Info\n"
		+"	9.   Files Containing Passwords\n"
		+"	10.  Sensitive Online Shopping Info\n"
		+"	11.  Network or Vulnerability Data\n"
		+"	12.  Pages Containing Login Portals\n"
		+"	13.  Various Online Devices\n"
		+"	14.  Advisories and Vulnerabilities\n\n"
		)

	# Add in argument options
	parser = argparse.ArgumentParser(description=description, formatter_class=RawTextHelpFormatter)
	parser.add_argument('-s', '--search', action='store', dest='search', help='Search text')
	#parser.add_argument('-sr', '--search-regix', action='store', dest='search_regix', help='Regular expression search pattern')
	parser.add_argument('-ps', '--position-start', action='store', dest='position_start', help='Start at this position', type=int)
	parser.add_argument('-n', '--no-of-results', action='store', dest='no_of_results', help='Number of results to fetch', type=int)
	parser.add_argument('-c', '--category-no', action='store', dest='category_no', help='Category number', type=int, choices=range(1,15))
	parser.add_argument('-o', '--output', action='store', dest='output', help='Output file', default="dorks.txt")

	if len(sys.argv)==1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	arguments = parser.parse_args()

	if arguments.search != None:
		params["search"] = arguments.search
	#if arguments.search_regix != None:
	#	params["search"] = arguments.search_regix
	#	params["search_regix"] = "true"
	if arguments.position_start != None:
		params["page_start"] = str(arguments.position_start)
	if arguments.no_of_results != None:
		params["page_finish"] = str(arguments.no_of_results)
	if arguments.category_no != None:
		params["category_no"] = str(arguments.category_no)
	if arguments.output != None: #check if exists
		output_file = arguments.output

	#get dorks
	get_dorks(params, output_file)
pass

def get_dorks(params, output_file):
	response = search(params)

	if response.status_code != requests.codes.ok:
	    print ("[ERROR] Response not Ok. (code "+ response.status_code +")")
	    print(response.headers)
	    exit()

	# dump response  to file 
	out = open(output_file+".dump","w")
	out.write(str(response.text))
	out.close()

	# process response
	results  = response.json()

	print ("[+] Total dorks: "+ str(results["recordsTotal"]))
	print ("[+] Filtered by search: "+ str(results["recordsFiltered"]))
	print ("[+] Dorks retrieved: " + str(len(results["data"])))
	print ("\n[+] Dorks: \n")

	if int(results["recordsFiltered"]) == 0:
		print ("Zero records found!")
	try:
		out = open(output_file,"w")
		for dork in results["data"]:
		    dorka = grep_dork(dork["url_title"])
		    print (dorka) #handle non printable chars
		    out.write(dorka)
		    out.write("\n")
		
		
		print ("\n[+] Dorks saved to file: " + output_file)
		print ("[+] Response dumped to file: " + output_file +".dump")
		print ("\n[+] Done!")
		pass
	except Exception as e:
		print('Execption: ' + str(e))

	finally:
		out.close()
		pass
pass

def grep_dork(dork_link):
	d= re.sub(r'<a href="/ghdb/\d+">', "", dork_link)
	dorka= re.sub(r'</a>', "", d)
	return dorka
pass

def search(params):
	if params == None or params == {}:
		params["page_start"] = "1"
		params["page_finish"] = "20"
		params["search"] = ""
		params["search_regix"] = "false"
		params["category_no"] = ""

	base_uri = "https://www.exploit-db.com/google-hacking-database"
	query_string = ("?draw=3&columns%5B0%5D%5Bdata%5D=date&columns%5B0%5D%5Bname%5D=date&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=url_title&columns%5B1%5D%5Bname%5D=url_title&columns%5B1%5D%5Bsearchable%5D=true&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=cat_id&columns%5B2%5D%5Bname%5D=cat_id&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=author_id&columns%5B3%5D%5Bname%5D=author_id&columns%5B3%5D%5Bsearchable%5D=false&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=desc&"+
	"start=" + params["page_start"]
	+"&length=" + params["page_finish"]
	+"&search%5Bvalue%5D=" + params["search"]
	+"&search%5Bregex%5D=" + params["search_regix"]
	+"&author=&category=" + params["category_no"]
	+"&_=1587067609102")
	
	headers= {
	"Host": "www.exploit-db.com",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
	"Accept": "application/json, text/javascript, */*; q=0.01",
	"Accept-Language": "en-US,en;q=0.5",
	"Accept-Encoding": "gzip, deflate, br",
	"Referer": "https://www.exploit-db.com/google-hacking-database",
	"X-Requested-With": "XMLHttpRequest",
	"DNT": "1",
	"Connection": "keep-alive",
	"TE": "Trailers"
	}
	response = requests.get(base_uri+query_string, headers=headers)
	return response
pass


if __name__ == '__main__':
    exit(main())
