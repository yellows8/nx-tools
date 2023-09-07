#!/usr/bin/python3
import os
import sys
import struct
import binascii
from os.path import exists
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def bdf_read(path):
    out = []
    if os.path.exists(path):
        with open(path, 'rb') as tmpf:
            data = tmpf.read()
            magicnum, entrycount = struct.unpack('<II', data[0x0:0x8])
            if magicnum!=0x546c7373:
                print("Bad magicnum (0x%x) for bdf_read('%s')." % (magicnum, path))
                out = None
            else:
                for i in range(entrycount):
                    pos = 0x8+i*0x10
                    entry_id, status, data_size, data_offset = struct.unpack('<IIII', data[pos:pos+0x10])
                    entry = {'id': entry_id, 'status': status, 'data_size': data_size, 'data_offset': data_offset}
                    entrydata = data[0x8+data_offset:0x8+data_offset+data_size]
                    entry['data'] = entrydata
                    if path.find("TrustedCerts")!=-1:
                        entry['data_x509'] = x509.load_der_x509_certificate(entrydata)
                    out.append(entry)
    else:
        print("bdf_read(): File doesn't exist: %s" % (path))
        out = None
    return out

def bdf_diff(prev, cur):
    out = []

    if prev is None or len(prev)==0:
        print("bdf_diff: prev is empty / {error occured during bdf_read}.")
        return None

    if cur is None or len(cur)==0:
        print("bdf_diff: cur is empty / {error occured during bdf_read}.")
        return None

    for entry in cur:
        found = False
        entrytype = None
        status_updated = False
        data_updated = False

        for prev_entry in prev:
            if entry['id'] == prev_entry['id']:
                found = True
                if entry['status'] != prev_entry['status']:
                    status_updated = True
                    entrytype = 'updated'
                if entry['data'] != prev_entry['data']:
                    data_updated = True
                    entrytype = 'updated'
                if status_updated is False and data_updated is False:
                    entrytype = 'none'
                break
        if found is False:
            entrytype = 'added'
        if entrytype is not None and entrytype!='none':
            ent = {'type': entrytype, 'status_updated': status_updated, 'data_updated': data_updated, 'entry': entry}
            out.append(ent)

    status_updated = False
    data_updated = False

    for prev_entry in prev:
        found = False
        for entry in cur:
            if entry['id'] == prev_entry['id']:
                found = True
                break
        if found is False:
            entrytype = 'removed'
            ent = {'type': entrytype, 'status_updated': status_updated, 'data_updated': data_updated, 'entry': entry}
            out.append(ent)
    return out

if __name__ == "__main__":
    if len(sys.argv)>1:
        out = bdf_read(sys.argv[1])
        print("[")
        for entry in out:
            if 'data_x509' in entry:
                ent_x509 = entry['data_x509']
                fingerprint = binascii.hexlify(ent_x509.fingerprint(hashes.SHA256())).decode('utf-8')
                tmpstr = ", 'x509': {'fingerprint': '%s', ' serial_number': '0x%X', 'not_valid_before': '%s', 'not_valid_after': '%s', 'issuer': '%s', 'subject': '%s', 'signature_algorithm_oid': '%s'}" % (fingerprint, ent_x509.serial_number, ent_x509.not_valid_before, ent_x509.not_valid_after, ent_x509.issuer, ent_x509.subject, ent_x509.signature_algorithm_oid)
            else:
                tmpstr = ""
            print("{'id': %d, 'status': %d, 'data_size': 0x%X, 'data_offset': 0x%X%s}," % (entry['id'], entry['status'], entry['data_size'], entry['data_offset'], tmpstr))
        print("]")
    else:
        print("Usage:\n%s <ssl .bdf path>" % (sys.argv[0]))

