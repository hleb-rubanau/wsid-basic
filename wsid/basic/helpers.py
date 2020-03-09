import requests 

def normalize_identifier(url):
    url=url.split('?')[0]
    url=url.split('://')[-1]
    url=url.strip('/')
    return f'https://{url}'


def get_remote_metadata(identity, item):
    url = normalize_identifier(identity)
    result = requests.get(f'{identity}/{item}')
    if result.status_code==200:
        return result.text
    else:
        return ''
