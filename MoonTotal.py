#!/usr/bin/python3

# [+]==================[Creditos]==================[+]
#  #                                                #
#  #     Devs: Ghosty / xNullCode / Deneb           #
#  #     Discord:                                   #
#  #        Ghostykdi#7168                          #
#  #     Derechos de Author:                        #
#  #         Ghosty / xNullCode / Deneb             #
# [+]==================[Creditos]==================[+]
#
#                        |\**/|
#                        \ == /
#                         |  |
#                         |  |
#                         \  /
#                          \/
#
# [+]==================[Start Code]==================[+]
#

import json, requests, os, pwn, time, pyfade, argparse, socket
from colorama import *
from os import system
from pwn import *
from pyfade import Fade, Colors

with open('config.json', 'r') as file:
    config = json.load(file)

VTotal = config['VIRUSTOTAL_API_KEY']
VTotal_Status = False

if len(VTotal) >= 64:
    VTotal_Status = True

Domain_or_Subdomains = ""

class DenebS4c():

    def __init__(self):
        self.main()

    def main(self):
        
        if os.name == "nt":
            system("cls")
        else:
            system("clear")
        
        self.banner()

        parser = argparse.ArgumentParser()
        parser.add_argument('-d','--domain', help="Domain for find ip's history or subdomains.")
        parser.add_argument('-o','--options', help="Select option: <subd> <ips>")
        
        args = str(parser.parse_args())
        args2 = args.split("'")
        if args == "Namespace(domain=None, options=None)":
            parser.print_help()
        try:
            if args2[3] == "subd":
                self.Subdomains(args2[1])
            elif args2[3] == "ips":
                self.IP_History(args2[1])
            else:
                parser.print_help()
        except:
            pass

    def banner(self):
        print(Fade.Horizontal(Colors.blue_to_cyan,r"""
o                     __...__     *               
              *   .--'    __.=-.             o
     |          ./     .-'     
    -O-        /      /   
     |        /    '"/               *
             |     (@)                              { Developer » DenebS4c }
            |        \                         .    { VirusTotal API » %s }
            |         \
 *          |       ___\                  |
             |  .   /  `                 -O-
              \  `~~\                     |
         o     \     \            *         
                `\    `-.__           .  
    .             `--._    `--'
                       `---~~`                *
            *                   o
        """% (VTotal_Status)))


    def IP_History(self, domain):
        p1 = log.progress("Deneb IP's History")
        p1.status("Scanning » "+domain)
        api_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey':config['VIRUSTOTAL_API_KEY'],'domain':domain}
        response = requests.get(api_url, params=params)
        Parms = response.json()

        print("-"*80)
        print(f"""\tFecha\t\t\tHora\t\t\tIP's\t\t\t
"""+"-"*80)

        for ips in Parms['resolutions']:
            resolved = ips['last_resolved'].split(" ")
            fecha = resolved[0]
            Hora = resolved[1]
            IP_Historys = ips['ip_address']
            print(f"\t{fecha}\t\t{Hora}\t\t{IP_Historys}")
            #print(fecha + "\t\t" + Hora + "\t\t" + IP_Historys)
       

    def Subdomains(self, domain):
        api_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey':config['VIRUSTOTAL_API_KEY'],'domain':domain}
        response = requests.get(api_url, params=params)
        Parms = response.json()

        p1 = log.progress("Deneb Subdomain Finder") 
        p1.status("Scanning » "+domain)

        print("-"*80)
        print(f"""\tSubdomains\t\t\t\tIP's
"""+"-"*80)
        
        for ips in Parms['subdomains']:
            SubD = ips
            SubD_IP=SubD.split(" ")
            for ip in SubD_IP:
                time.sleep(0.2)
                try:
                    IP_Sub = socket.gethostbyname(ip)
                    sad = f"\t{SubD}\t\t\t"+IP_Sub
                except:
                    sad = f"\t{SubD}\t\t\tNot Found"
            #ad.strip()
            print(sad)

DenebS4c()


#
# [+]==================[End Code]==================[+]
#
#                          /\           
#                         /  \    
#                         |  |     
#                         |  |     
#                        / == \    
#                        |/**\|  
#    
# [+]==================[Creditos]==================[+]
#  #                                                #
#  #     Devs: Ghosty / xNullCode / Deneb           #
#  #     Discord:                                   #
#  #        Ghostykdi#7168                          #
#  #     Derechos de Author:                        #
#  #         Ghosty / xNullCode / Deneb             #
# [+]==================[Creditos]==================[+]