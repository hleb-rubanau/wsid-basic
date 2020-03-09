
def normalize_identifier(raw_url):
    url=url.split('?')[0]
    url=url.split('://')[-1]
    url=url.strip('/')
    return f'https://{url}'


def get_remote_metadata(identity, item):
    url = normalize_identifier(identity)
    return requests.get(f'{identity}/{item}')