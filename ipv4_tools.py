# On suppose que les adresses IPv4 & masques fournis sont sous leur répresentation classique, c-à-d xxx.xxx.xxx.xxx où xxx<=255

import re #expressions régulières


def conv_IPnum_vers_IPbin (ip) : #convertit une representation numérique d'adresse IP en binaire
    return "".join ( [dec2bin(int(i)) for i in ip.split('.') ] )

def conv_IPbin_vers_IPnum (ip) : #convertit une adresse IP binaire en représentation numérique
    return "".join ( [str(int( i , 2)) +'.' for i in [ ip[0:8] , ip[8:16] , ip[16:24] , ip[24:32] ] ] )[:-1]

def dec2bin(dec): #convertit decimal vers binaire, rajoute des '0' pour retourner 8 bits
    return "0"* (8-len("{0:b}".format(dec) ) ) +"{0:b}".format(dec)

def masque_vers_CIDR(masque): #convertit la notation numérique du masque en notation CIDR
    return len( re.search('(11*)(0*)' , conv_IPnum_vers_IPbin(masque) ) .group(1) )

def adresse_reseau_bin(ip, masque): #retourne l'adresse réseau à partir d'une IP et d'un masque donné, en binaire
    n = masque_vers_CIDR(masque)
    return conv_IPnum_vers_IPbin(ip)[0:n]+'0'*(32-n)

def adresse_reseau(ip, masque): #retourne l'adresse réseau à partir d'une IP et d'un masque donné, en numérique
    return conv_IPbin_vers_IPnum ( adresse_reseau_bin(ip,masque) )

def adresse_broadcast_bin(ip, masque): #retourne l'adresse broadcast à partir d'une IP et d'un masque donné, en binaire
    n = masque_vers_CIDR(masque)
    return conv_IPnum_vers_IPbin(ip)[0:n]+'1'*(32-n)

def adresse_broadcast(ip,masque): #retourne l'adresse broadcast à partir d'une IP et d'un masque donné, en numérique
    return conv_IPbin_vers_IPnum ( adresse_broadcast_bin(ip,masque) )

def rang_adresse_assignables(ip, masque): #retourne la première et la dernière adresse assignable du réseau de l'adresse & du masque donnés
    n = masque_vers_CIDR(masque)
    return [ conv_IPbin_vers_IPnum ( adresse_reseau_bin(ip,masque)[:31]+'1' ) , conv_IPbin_vers_IPnum ( adresse_broadcast_bin(ip,masque)[:31]+'0' ) ]

def masque_generique(ip_debut, ip_fin): #retourne le masque générique pour sélectionner toutes les adresses comprises entre celles données en paramètre, utile pour les ACL
    return "".join(str(int(ip_fin.split('.')[i] ) - int(ip_debut.split('.')[i] ) ) + '.' for i in range(4) )[:-1]
    
