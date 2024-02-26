# Procksy

## Simple proxy

```bash
procksy serve
```

```bash
curl --socks5-hostname 127.0.0.1:9500 https://google.com/
```

## Authenticating and filtering proxy

```bash
procksy serve \
        --users \
        'test:$argon2id$v=19$m=65536,t=3,p=4$QTsy7ftyag4XJ0GPajoq7g$WBpOw5ZK5i+uXuzukuVCIJqpUDHEYzm2DD8b3XYrz8k' \
        --client-filter 'allow:127.0.0.1' \
        --target-filter 'allow:example.com:443,google.com,www.google.com'
```

```bash
curl -U test --socks5-hostname https://google.com/
```

## Configuration template

```json
{
    "client_filter": {
        "mode": "allow",
        "values": [
            "127.0.0.1"
        ],
        "filepath": null
    },
    "target_filter": {
        "mode": "allow",
        "values": [
            "example.com"
        ],
        "filepath": null
    },
    "authenticator": {
        "enabled": false,
        "users": {
            "test": "$argon2id$v=19$m=65536,t=3,p=4$QTsy7ftyag4XJ0GPajoq7g$WBpOw5ZK5i+uXuzukuVCIJqpUDHEYzm2DD8b3XYrz8k"
        }
    },
    "bind_addr": "127.0.0.1",
    "bind_port": 9050,
    "buffer_size": 2048,
    "max_threads": 200,
    "sock_timeout": 5
}
```
