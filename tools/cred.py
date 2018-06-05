#!/usr/bin/env python
from types import ListType, DictType
from OpenSSL import crypto
try:
    from cbor2 import dump, load
except ImportError as ex:
    print("Can not start script: ", ex)
    print("#pip install cbor2")
from os.path import exists
from termcolor import colored
from binascii import hexlify
#---------------constants---------------------
cred_file = 'port/linux/mfgserver_creds/cred_0'
#---------------functions---------------------
def dict_parse(d):
    for key, value in d.iteritems():
        print(" key: ", key);
        if type(value) is ListType:
            list_parse(value)
        elif type(value) is DictType:
            dict_parse(value)
        else:
            print(" value: ", value, " type; ", type(value))

def list_parse(l):
    for value in l:
        if type(value) is DictType:
            dict_parse(value)
        elif type(value) is ListType:
            list_parse(value)
        else:
            print(" value: ", value, " type; ", type(value))

def cred_parse(cred):
    for cred_key, cred_value in cred.iteritems():
        if cred_key == 'credid':
            print("credid: %d"%cred_value)
        elif cred_key == 'subjectuuid':
            print("subjectuuid: %s"%cred_value)
        elif cred_key == 'credusage':
            print("credusage: %s"%cred_value)
        elif cred_key == 'publicdata':
            for cert_key, cert_value in cred_value.iteritems():
                if cert_key == 'data':
                    cert_data = cert_value
                elif cert_key == 'encoding':
                    print("encoding: %s"%cert_value)
                    if cert_value == 'oic.sec.encoding.der':
                        cert_encoding = crypto.FILETYPE_ASN1
                    elif cert_value == 'oic.sec.encoding.pem':
                        cert_encoding = crypto.FILETYPE_PEM
            parse_x509(cert_data, cert_encoding)

def print_x509_name(name):
    print("\tcountryName:\t\t%s"%name.countryName)
    print("\tstateOrProvinceName:\t%s"%name.stateOrProvinceName)
    print("\tlocalityName:\t\t%s"%name.localityName)
    print("\torganizationName:\t%s"%name.organizationName)
    print("\torganizationalUnitName:\t%s"%name.organizationalUnitName)
    print("\tcommonName:\t\t%s"%name.commonName)
    print("\temailAddress:\t\t%s"%name.emailAddress)

def asn1_time(t):
    #YYYYMMDDhhmmssZ
    return(t[0:4]+"-"+t[4:6]+"-"+t[6:8]+" "+t[8:10]+":"+t[10:12]+":"+t[12:14])

def get_key_type(t):
    if t == crypto.TYPE_DSA:
        return "DSA"
    elif t == crypto.TYPE_RSA:
        return "RSA"
    else:
        return "Unknown type: %d"%t

def parse_x509(cert_buf, cert_type):
    c = crypto
    cert = c.load_certificate(cert_type, cert_buf)
    print("  issuer: ")
    print_x509_name(cert.get_issuer())
    print("  version: %d"%cert.get_version())
    print("  not after: %s"%asn1_time(cert.get_notAfter()))
    print("  not before: %s"%asn1_time(cert.get_notBefore()))
    print("  is expired: %s"%cert.has_expired())
    pubkey = cert.get_pubkey()
    print("  public key: bits: %d type: %s"%(pubkey.bits(), get_key_type(pubkey.type())))
    print("%s"%crypto.dump_publickey(crypto.FILETYPE_PEM,pubkey).rstrip());
    print("  serial number: %d"%cert.get_serial_number())
    print("  signature algorithm: %s"%cert.get_signature_algorithm())
    print("  subject: ")
    print_x509_name(cert.get_subject())
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        print("    %s: %s"%(ext.get_short_name(),hexlify(ext.get_data())))
    print("%s"%crypto.dump_certificate(crypto.FILETYPE_PEM,cert).rstrip());

#---------------main--------------------------
try:
    if not exists(cred_file):
        print("file: %s not found"%cred_file)
        exit(1)
    with open(cred_file, 'rb') as fp:
        obj = load(fp)
        fp.close()
        for key, value in obj.iteritems():
            if key == 'creds':
                creds = value
                for cred in creds:
                    cred_parse(cred)
                continue
            elif key == 'rowneruuid':
                print("rowneruuid: %s"%value)
            elif key == 'rt':
                print("rt: %s"%value)
            elif key == 'if':
                print("if: %s"%value)
            elif type(value) is ListType:
                list_parse(value);
            elif type(value) is DictType:
                dict_parse(value)
            else:
                print("key: ", key);
                print(" value: ", value, " type; ", type(value))
    credid = len(creds) + 1
    while(credid > len(creds)):
        credid = int(raw_input("select credid(%s):"%len(creds))) - 1
        print("you are selecting: %s"%(credid+1))
    if credid < len(creds):
        cred_file = raw_input("input certificare file(pem):")
        if exists(cred_file):
            with open(cred_file, 'rb') as fp:
                cred = crypto.load_certificate(crypto.FILETYPE_PEM,fp.read())
                creds[credid]['publicdata']['data'] = crypto.dump_certificate(crypto.FILETYPE_ASN1,cred)
        cred_parse(creds[credid])
    with open(cred_file+".new", 'wb') as fp:
        dump(obj, fp)
        fp.close()
except Exception as ex:
    print("main exception: ",ex)
