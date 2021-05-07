# httpcap

http request/response recorder based on gopacket(tcpdump).

## usage

1. build: `go install -ldflags="-s -w" ./...`
1. start listening server for test: `httplive`
1. start httpcap: `sudo httpcap -f "tcp and dst port 5003"  -i lo0`
1. revoke `http http://127.0.0.1:5003/api/demo`
1. revoke `http http://127.0.0.1:5003/echo/demo name=bingoo`

```sh
🕙[2021-05-08 05:13:22.234] ❯ sudo httpcap -p 5003  -i lo0
2021/05/08 05:13:24 Starting capture on interface "lo0"
2021/05/08 05:13:24 reading in packets
2021/05/08 05:14:00 [66]src:49472
2021/05/08 05:14:00 [67]src:5003
2021/05/08 05:14:00 [66]Received from stream [127.0.0.1->127.0.0.1] [49472->5003]
2021/05/08 05:14:00 request:
HOST 127.0.0.1:5003
GET /api/demo HTTP/1.1
User-Agent: HTTPie/2.4.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

2021/05/08 05:14:00 body size:0
2021/05/08 05:14:00 [67]Received from stream [127.0.0.1->127.0.0.1] [5003->49472]
2021/05/08 05:14:00 response:
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Fri, 07 May 2021 21:14:00 GMT
Content-Length: 179

2021/05/08 05:14:00 body size:179, body:{
  "array": [
    1,
    2,
    3
  ],
  "boolean": true,
  "null": null,
  "number": 123,
  "object": {
    "a": "b",
    "c": "d",
    "e": "f"
  },
  "string": "Hello World"
}, error:<nil>
2021/05/08 05:14:00 [68]src:5003
2021/05/08 05:14:09 [11]src:49495
2021/05/08 05:14:09 [12]src:5003
2021/05/08 05:14:09 [11]Received from stream [127.0.0.1->127.0.0.1] [49495->5003]
2021/05/08 05:14:09 request:
HOST 127.0.0.1:5003
POST /echo/demo HTTP/1.1
Content-Length: 18
User-Agent: HTTPie/2.4.0
Accept-Encoding: gzip, deflate
Accept: application/json, */*;q=0.5
Connection: keep-alive
Content-Type: application/json

2021/05/08 05:14:09 body size:18, body:{"name": "bingoo"}, error:<nil>
2021/05/08 05:14:09 [12]Received from stream [127.0.0.1->127.0.0.1] [5003->49495]
2021/05/08 05:14:09 response:
HTTP/1.1 200 OK
Date: Fri, 07 May 2021 21:14:09 GMT
Content-Length: 481
Content-Type: application/json; charset=utf-8

2021/05/08 05:14:09 body size:481, body:{"headers":{"Accept":"application/json, */*;q=0.5","Accept-Encoding":"gzip, deflate","Connection":"keep-alive","Content-Length":"18","Content-Type":"application/json","User-Agent":"HTTPie/2.4.0"},"host":"127.0.0.1:5003","method":"POST","payload":{"name":"bingoo"},"proto":"HTTP/1.1","remoteAddr":"127.0.0.1:49495","requestUri":"/echo/demo","router":"/echo/:id","routerParams":{"id":"demo"},"timeGo":"2021-05-08 05:14:09.0587","timeTo":"2021-05-08 05:14:09.0587","url":"/echo/demo"}, error:<nil>
```

## resources

1. [tcpdump](https://danielmiessler.com/study/tcpdump/)
1. [gopacket exapmle httpassembly](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go)
1. [asmcos sniffer](https://github.com/asmcos/sniffer/blob/master/sniffer.go)
