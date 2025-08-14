## About

This is a dockerized version of [outline-ss-server](https://github.com/Jigsaw-Code/outline-ss-server) and an example implementation of [this proposal](https://github.com/Jigsaw-Code/outline-apps/issues/2560).

## Usage

1. Edit [docker-compose.yml](https://github.com/zonescape/outline-ss-server/blob/master/docker-compose.example.yml) and [config.yml](https://github.com/zonescape/outline-ss-server/blob/master/config.example.yml) and copy them to your server

2. Run

```
docker compose up -d
```

3. Generate static access key in QR or URI form

```
# QR 
docker run --rm ghcr.io/zonescape/outline-ss-server keygen --addr 1.2.3.4:443 --secret qwerty --prefix 'HTTP%2F1.1%20' --qr
<output omitted>

# URI
docker run --rm ghcr.io/zonescape/outline-ss-server keygen --addr 1.2.3.4:443 --secret qwerty --prefix 'HTTP%2F1.1%20'
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxd2VydHk=@1.2.3.4:443/?outline=1&prefix=HTTP%2F1.1%20
```
Note: access key generator is currently limited to `ss://` links. It means only `tcp` and `udp` server listeners are supported.

4. Install [Outline client](https://getoutline.org/en-GB/get-started/#step-3)

5. Scan generated QR (or open URI) on the device where you have Outline client installed

## keygen options

```
$ docker run --rm ghcr.io/zonescape/outline-ss-server keygen --help

Usage:
  keygen [OPTIONS]

Application Options:
      --addr=   address of outline-ss-server in host:port form
      --cipher= cipher from config.yml (default: chacha20-ietf-poly1305)
      --secret= secret from config.yml. It will be asked via terminal if absent. [$SECRET]
      --prefix= URL encoded obfuscation prefix. Visit
                https://developers.google.com/outline/docs/guides/service-providers/prefixing
                for recommended values.
      --qr      generate QR code

Help Options:
  -h, --help    Show this help message
```

## Implementaton notes

- `outline-ss-server` is vendored as a Go tool using these commands

```
go get -tool github.com/Jigsaw-Code/outline-ss-server/cmd/outline-ss-server@vX.Y.Z
go mod tidy
go mod vendor
```
