"""One way to make a credentialed request: without following redirects.

urllib follows a 3xx on its own and carries every header set on the Request
across - `Authorization`, `X-FTL-SID` and the rest - to wherever the Location
header points, including another host. A source's credential should reach the
address that was configured for it and nowhere else, so a redirect here is an
error that names where it wanted to go; the fix is to configure that address
directly, which is a decision a person makes, not one a server makes for us.
"""
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError(
            f"HTTP {code} redirect to {newurl} refused - credentials are only "
            "sent to the configured address; set the source URL to the final one")


def urlopen(req, timeout: float, context=None):
    handlers = [NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)
