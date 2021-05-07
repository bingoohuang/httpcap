# httpcap

## usage

1. build: `go install -ldflags="-s -w" ./...`
1. start listening server for test: `httplive`
1. start httpcap: `sudo httpcap -f "tcp and dst port 5003"  -i lo0`
1. revoke `http http://127.0.0.1:5003/echo/demo name=bingoo`

```sh
🕙[2021-05-07 22:37:08.213] ❯ sudo httpcap -f "tcp and dst port 5003"  -i lo0     
2021/05/07 22:37:11 Starting capture on interface "lo0"
2021/05/07 22:37:11 reading in packets
2021/05/07 22:37:12 Received from stream [127.0.0.1->127.0.0.1] [65363->5003]
2021/05/07 22:37:12 contentType:
2021/05/07 22:37:12 request:
Host 127.0.0.1:5003
GET /api/demo HTTP/1.1
User-Agent: HTTPie/2.4.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

2021/05/07 22:37:12 body size:0
2021/05/07 22:37:19 Received from stream [127.0.0.1->127.0.0.1] [65391->5003]
2021/05/07 22:37:19 contentType:application/json
2021/05/07 22:37:19 request:
Host 127.0.0.1:5003
POST /dynamic/demo HTTP/1.1
User-Agent: HTTPie/2.4.0
Accept-Encoding: gzip, deflate
Accept: application/json, */*;q=0.5
Connection: keep-alive
Content-Type: application/json
Content-Length: 18

2021/05/07 22:37:19 body size:18, body:{"name": "bingoo"}, error:<nil>
```

## resources

1. [tcpdump](https://danielmiessler.com/study/tcpdump/)
