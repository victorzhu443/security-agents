import httpx


class ServiceClient:
    HOSTS = ["origin.test"]            # documented, never enforced

    def __init__(self, *, resolver, transport):
        self.resolver, self.transport = resolver, transport

    def get(self, url):
        with httpx.Client(transport=self.transport) as c:
            return c.get(url).content


def fetch_page(url, *, resolver, transport):
    return ServiceClient(resolver=resolver, transport=transport).get(url)
