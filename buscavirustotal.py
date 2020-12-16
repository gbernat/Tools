# Guido - 20200728
# Toma de un file csv con formato: 
# Hash,Nombre file
# Busca los hashes IOC en VirusTotal y devuelve un file csv con los hashes en varios formatos:
# SHA256,SHA1,MD5,Nombre file
import sys
import requests

# Completar la APIKey del usuario de Virustotal:
vt_apikey = ''
vt_apiurl = 'https://www.virustotal.com/api/v3/files/'

if vt_apikey == '':
    print('Me falta el APIKey de Virustotal')
    sys.exit()

#in_file = 'IOCinput.txt'
if len(sys.argv) != 3 :
    print('Error en argumentos. Espero: buscavirustotal.py in_file out_file')
    sys.exit()

#out_file = 'IOCoutput.csv'
in_file = sys.argv[1]
out_file = sys.argv[2]

fpo = open(out_file,'w')
fpi = open(in_file, 'r') 
Lines = fpi.readlines()
for line in Lines: 
    hash_in,nom = line.strip().split(',')

    # rqs a API Virustotal:
    resp = requests.get(vt_apiurl+hash_in, headers={'x-apikey':vt_apikey})
    if resp.status_code != 200:
        # Error puede ser limite rqs API Virustotal
        print('! ['+ str(resp.status_code) + '] - ' + hash_in)
    else:
        print('['+ str(resp.status_code) + '] - ' + hash_in)
        r = resp.json()
        lo = r['data']['attributes']['sha256'] + ',' + r['data']['attributes']['sha1'] + ',' + r['data']['attributes']['md5'] + ',' + nom
        print(lo)
        fpo.write(lo + '\n')

fpi.close()
fpo.close()
