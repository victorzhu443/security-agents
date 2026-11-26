from secprim.safe_fetch import safe_fetch


class ServiceClient:
    HOSTS = ["origin.test"]
    MAX_BYTES = 1000

    def __init__(self, *, resolver, transport):
        self.resolver, self.transport = resolver, transport

    def get(self, url):
        return safe_fetch(url, allow_hosts=self.HOSTS, max_bytes=self.MAX_BYTES,
                          resolver=self.resolver, transport=self.transport).content


def fetch_page(url, *, resolver, transport):
    return ServiceClient(resolver=resolver, transport=transport).get(url)
