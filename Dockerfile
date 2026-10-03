# python:3.12-slim, pinned by digest 2026-09-11. A tag moves; a digest
# does not, so a rebuild reproduces the image that is running instead of
# whatever the tag points at today. Base-image patches now arrive only
# when this line is changed on purpose — that is the trade, and it is
# deliberate. Refresh with:
#   docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install -r requirements.txt

# The app runs as an ordinary user, not root. Nothing it does needs root:
# port 8087 is unprivileged, the scans are plain TCP connects, and Docker is
# reached over HTTP through the socket proxy. The UID matches the owner of
# ./data on the host (1000 is the first user on most Linux systems), so the
# database stays readable there without sudo; build with
# --build-arg NETMAP_UID=... if yours differs.
ARG NETMAP_UID=1000
ARG NETMAP_GID=1000
RUN groupadd -g "$NETMAP_GID" netmap \
 && useradd -u "$NETMAP_UID" -g netmap -M -d /srv -s /usr/sbin/nologin netmap \
 && mkdir -p /data && chown netmap:netmap /data

# Code stays root-owned: the app can read it and cannot change it. The chmod
# makes that true whatever modes the build machine's checkout has — a file
# saved owner-only (rw-------) there would otherwise be unreadable here.
COPY app ./app
COPY CHANGELOG.md .
RUN chmod -R a+rX /srv/app /srv/CHANGELOG.md

ENV NETMAP_DB=/data/netmap.db
# Whose X-Forwarded-For / -Proto to believe: the proxies in front — NPM and
# cloudflared on the Docker network — and nobody else. It used to be "*",
# which let any client claim to be forwarding for any address. Docker's
# bridge networks live in 172.16.0.0/12; override in compose if yours differ.
ENV FORWARDED_ALLOW_IPS=127.0.0.1,172.16.0.0/12
VOLUME ["/data"]
EXPOSE 8087
USER netmap

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8087/healthz',timeout=4).status==200 else 1)"

# --forwarded-allow-ips is left out so uvicorn reads FORWARDED_ALLOW_IPS above.
CMD ["uvicorn","app.main:application","--host","0.0.0.0","--port","8087","--proxy-headers"]
