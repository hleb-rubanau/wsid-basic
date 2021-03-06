import logging

class PatternError(Exception):
    pass

def validator(pattern, logger=None):

    if not logger:
        logger=logging.getLogger('wsid.basic.simple_policy.dummy')
        logger.setLevel(logging.FATAL)

    pattern=pattern.strip().strip('/')

    #if '*' in pattern.strip('*'):
    #    raise  PatternError(f"Wildcards in the middle: {pattern}")
    if '://' in pattern:
        raise PatternError(f"Schema in the pattern: {pattern}'")
    if '?' in pattern:
        raise PatternError(f"Prohibited sign '?': {pattern}")
    if not '.' in pattern:
        raise PatternError(f"Pattern must include domain name: {pattern}")
    if pattern.endswith('*'):
        if not '/' in pattern:
            raise PatternError(f'Trailing wildcards are not allowed in domain names: {pattern}')    
    if pattern.startswith('*'): 
        if not pattern.startswith('*.'):
            raise PatternError(f'Leading wildcards may only denote subdomains: {pattern}')
     

    pattern_domain = pattern.split('/')[0]
    if not pattern_domain:
        raise PatternError(f"Domain missing: {pattern}")

    pattern_path_parts = pattern.split('/')
    if len(pattern_path_parts)==1:
        pattern_path_parts=['*'] # assuming whole path is wildcarded
    else:
        pattern_path_parts=pattern_path_parts[1:]        

    if pattern_domain.startswith('*.'):
        domainparts = pattern_domain[2:].split('.')
        if len(domainparts)<2 or not(all(domainparts)):
            raise PatternError(f"Too permissive wildcards in domain part (only third-level subdomains and below could be wildcarded): {pattern_domain}")
    elif '*' in pattern_domain:
        raise PatternError("Only complete subdomains could be wildcarded: {pattern_domain}")

    if any([ (('*' in p) and not(p=='*')) for p in pattern_path_parts ]):
        bad_path = '/'+'/'.join(pattern_path_parts)
        raise PatternError(f"Only complete path parts may be wildcarded: {bad_path}")

    pattern_domain_parts=pattern_domain.split('.')

    def validate(url):
        url=url.strip().strip('/')
        if not url.startswith('https://'):
            url='https://'+url
        
        if '?' in url:
            logger.debug(f"validator {pattern}: rejecting {url}")
            return False

        schemaless_url=url[len('https://'):]
        domain_parts = schemaless_url.split('/')[0].split('.')
    
        if pattern_domain_parts[0]=='*':
            if not( domain_parts[-1*(len(pattern_domain_parts)-1):]==pattern_domain_parts[1:]):
                logger.debug(f"validator {pattern}: rejecting {url} per domain mismatch")
                return False
        else:
            if not( domain_parts == pattern_domain_parts ):
                logger.debug(f"validator {pattern}: rejecting {url} per domain mismatch")
                return False

        path_parts = schemaless_url.split('/')
        if len(path_parts)==1:
            # identity could not be just domain
            logger.debug(f"validator {pattern}: rejecting {url} for lack of path part")
            return False

        # stripping off non-path part
        path_parts = path_parts[1:]
        
        if pattern_path_parts==['*']:
            logger.debug("All paths are matching to greedy wildcard ('/*'), accepting {'/'+'/'.join(path_parts)}")
            return True
        
        if not(len(path_parts)==len(pattern_path_parts)):
            logger.debug(f"validator {pattern}: rejecting {url} for path length mismatch. Expected: {len(pattern_path_parts)} ({pattern_path_parts}), got: {len(path_parts)} ({path_parts})")
            return False

        for i,e in enumerate(pattern_path_parts):
            p = path_parts[i]
            if e == '*':
                continue
            if not (e==p):
                logger.debug(f"validator {pattern}: rejecting {url} for path mismatch (expected: '{e}', got: '{p}')")
                return False
        
        logger.debug(f"validator {pattern}: confirmed {url}")
        return True

    return lambda x: validate(x)

def simple_ruleset(patterns, logger=None):

    if not logger:
        logger=logging.getLogger('wsid.basic.simple_policy.dummy')
        logger.setLevel(logging.FATAL)

    validation = []
    normalization = []

    for i, pattern in enumerate(patterns):
        pattern=pattern.strip()
        if pattern.startswith('!'):
            validation.append( validator(pattern[1:], logger) )
            normalization.append( lambda x: -1 if x else 0  )
        else:
            validation.append(  validator(pattern, logger) )
            normalization.append( lambda x: 1 if x else 0 )

    logger.debug(f"Ruleset built: {len(validation)} patterns")
    def validate(url):
        logger.debug(f"Ruleset: validating {url}")
        for i,v in enumerate(validation):
            raw_result = v(url)
            result = normalization[i]( raw_result )
            if result==0: 
                logger.debug(f"Pattern { patterns[i].strip() }: no match for '{url}', continuing")
                continue
            if result==1:
                logger.debug(f"Pattern { patterns[i].strip() }: matched '{url}', accepting")
                return True
            if result==-1:
                logger.debug(f"Pattern { patterns[i].strip() }: rejection match for '{url}', rejecting")
                return False

        logger.debug(f"Ruleset: no patterns match for {url}, rejecting by default")
        return False       
    
    return lambda x: validate(x)  
