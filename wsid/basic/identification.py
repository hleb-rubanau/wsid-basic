from cachetools import TTLCache
from .helpers import get_remote_metadata, normalize_identifier
import requests

@cached(cache=TTLCache(maxsize=1024,TTL=30))
def get_password_hashes(identity):    
    return [ m for m in 
                get_remote_metadata( identity, 'passwdhash' ).text.split('\n') 
            if m ]


@cached(cache=TTLCache(maxsize=1024,TTL=30))
def get_public_ssh_keys(raw_identity, overwrite_comments=True):
    identity = normalize_identifier(raw_identity)
    keybodies = [ k for k in 
                    get_remote_metadata(identity, 
                                        'id_ed25519.pub').text.split('\n') 
                  if k ]

    logger=logging.getLogger('wsid.basic')
    authorized_keys=[]
    for k in keybodies:
        fields=k.strip().split(' ')
        if len(fields)==2:  
            fields.append(identity)
        elif len(fields)==3:
            if overwrite_comments:
                fields[2]=identity
        else:
            logger.warning(f"Skipping malformed key at {identity}: {fields}")
            continue
        authorized_keys.append(' '.join(fields))
    return authorized_keys
            

@cached(cache=TTLCache(maxsize=1024,TTL=30))
def get_remote_host_ssh_keys(domain):
    hostkeys = get_remote_metadata(f"https://{domain}/.wsid", 
                                    'ssh_host_ed25519.pub').text.split('\n')
    

    keytype_body_tuples =  [ k.split(" ") for k in hostkeys if k ]
    host_keytype_keybody_tuples = [ (domain, k[0], k[1]) for k in keytype_body_tuples ]
    return host_keytype_keybody_tuples
