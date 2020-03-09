from cachetools import TTLCache, cached
from .helpers import get_remote_metadata, normalize_identifier
import requests
import nacl.pwhash
import logging
from nacl.exceptions import InvalidkeyError

CACHE_MAXSIZE=1024
CACHE_TTL=30

@cached(cache=TTLCache(maxsize=CACHE_MAXSIZE,ttl=CACHE_TTL))
def get_password_hashes(identity):    
    try:
        return [ m.encode() for m in 
                    get_remote_metadata( identity, 'passwdhash' ).text.split('\n') 
                if m ]
    except Exception as e:
        logging.getLogger('wsid.basic').warning(f"Failed to fetch password hashes for {identity}: {e}")
        return []

@cached(cache=TTLCache(maxsize=CACHE_MAXSIZE,ttl=CACHE_TTL))
def get_public_ssh_keys(raw_identity, overwrite_comments=True):
    identity = normalize_identifier(raw_identity)
    logger=logging.getLogger('wsid.basic')

    try:
        keybodies = [ k for k in 
                        get_remote_metadata(identity, 
                                            'id_ed25519.pub').text.split('\n') 
                      if k ]
    except Exception as e:
        logger.warning(f"Failed to fetch SSH public keys for {identity}: {e}")
        return []

    authorized_keys=[]
    for k in keybodies:
        fields=k.strip().split(' ')
        if fields[0].startswith('command'):
            logger.warning(f"Skipping insecure item at {identity}: {k}")
            
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
            

@cached(cache=TTLCache(maxsize=CACHE_MAXSIZE,ttl=CACHE_TTL))
def get_remote_host_ssh_keys(domain):
    hostkeys = get_remote_metadata(f"https://{domain}/.wsid", 
                                    'ssh_host_ed25519.pub').text.split('\n')
    

    keytype_body_tuples =  [ k.split(" ") for k in hostkeys if k ]
    host_keytype_keybody_tuples = [ (domain, k[0], k[1]) for k in keytype_body_tuples ]
    return host_keytype_keybody_tuples


class PasswordAuthenticator:

    def __init__(self, whitelist):
        self.whitelist=whitelist


    def authenticate(self, username, password):
        if not self.whitelist(username):
            return False

        hashes = get_password_hashes(username)
        for h in hashes:
            try: 
                if nacl.pwhash.verify(h, password):
                    return True
            except InvalidKeyError:
                continue

        return False
