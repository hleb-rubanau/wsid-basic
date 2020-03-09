class PatternError(Exception):
    pass

def validator(pattern):

    pattern=pattern.strip('/')

    if '*' in pattern.strip('*'):
        raise  PatternError(f"Wildcards in the middle: {pattern}")
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
        raise PatternError(f"Pattern must include path part: {pattern}")
    else:
        pattern_path_parts=pattern_path_parts[1:]        

    if pattern_domain.startswith('*.'):
        domainparts = pattern_domain[1:].split('.')
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
            return False
        if '?' in url:
            return False

        schemaless_url=url[len('https://'):]
        domain_parts = schemaless_url.split('/')[0].split('.')
    
        if pattern_domain_parts[0]=='*':
            if not( domain_parts[-1*(len(pattern_domain_parts)-1):]==pattern_domain_parts[1:]):
                return False
        else:
            if not( domain_parts == pattern_domain_parts ):
                return False

        path_parts = schemaless_url.split('/')
        if len(path_parts)==1:
            # identity could not be just domain
            return False

        # now complex maths
        if not(len(path_parts)==len(pattern_path_parts)):
            return False

        for i,e in enumerate(pattern_path_parts):
            p = path_parts[i]
            if e == '*':
                continue
            if not (e==p):
                return False
        return True

    return lambda x: validate(x)

def simple_ruleset(patterns):

    validation = []

    for pattern in patterns:
        if pattern.startswith('!'):
            v = validator(pattern[1:])
            validation.append( lambda x: -1 if v(x) else 0 )
        else:
            v = validator(pattern)
            validation.append( lambda x: 1 if v(x) else 0 )

    def validate(url):
        for v in validation:
            result = v(url)
            if result==0: 
                continue
            if result==1:
                return True
            if result==-1:
                return False

        return False       
    
    return lambda x: validate(x)  
