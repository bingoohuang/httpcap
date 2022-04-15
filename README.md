# httpcap

please goto https://github.com/gobars/httpdump

http request/response recorder based on gopacket(libpcap).

## install libpcap:

1. `sudo apt-get install libpcap-dev`
1. for ubuntu/debian: `sudo aptitude install libpcap-dev`
1. for centos/redhat/fedora: `sudo yum install libpcap-dev`

## usage

1. build: `go install -ldflags="-s -w" ./...`
1. start listening server for test: `httplive`
1. start httpcap: `sudo httpcap -f "tcp and dst port 5003"  -i lo0` or create conf.yml by `httpcap -init`, then edit it, then `sudo GOLOG_STDOUT=true httpcap -c conf.yml -resp`
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

1. [A cross platform http sniffer with a web UI](https://github.com/ga0/netgraph)
1. [capturing and replaying live HTTP traffic](https://github.com/buger/goreplay)
1. [tcpdump](https://danielmiessler.com/study/tcpdump/)
1. [gopacket exapmle httpassembly](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go)
1. [基于Go Packet实现网络数据包的捕获与分析](https://cloud.tencent.com/developer/article/1025427)
1. [asmcos sniffer](https://github.com/asmcos/sniffer/blob/master/sniffer.go)
1. [随机身份证号码生成](http://sfz.uzuzuz.com/?region=110101&birthday=19900307&sex=2&num=5&r=38)
1. [姓名生成器](https://www.qqxiuzi.cn/zh/xingming/)
