
import argparse
import asyncio
import ssl
import struct

import dns.message
import dns.query


async def read_dns_frame(reader):
    header = await reader.readexactly(2)
    length = struct.unpack("!H", header)[0]

    if length < 12 or length > 4096:
        raise ValueError("Invalid DNS message length")

    return await reader.readexactly(length)


def forward_to_unbound(wire, resolver, resolver_port):
    query = dns.message.from_wire(wire)

    response = dns.query.udp(
        query,
        resolver,
        port=resolver_port,
        timeout=5
    )

    if response.flags & 0x0200:
        response = dns.query.tcp(
            query,
            resolver,
            port=resolver_port,
            timeout=5
        )

    return response.to_wire()


async def handle_client(reader, writer, resolver, resolver_port):
    peer = writer.get_extra_info("peername")
    print(f"[DoT] Client connected: {peer}")

    try:
        while True:
            try:
                query_wire = await read_dns_frame(reader)
            except asyncio.IncompleteReadError:
                break

            try:
                loop = asyncio.get_running_loop()

                response_wire = await loop.run_in_executor(
                    None,
                    forward_to_unbound,
                    query_wire,
                    resolver,
                    resolver_port
                )

                response_frame = (
                    struct.pack("!H", len(response_wire))
                    + response_wire
                )

                writer.write(response_frame)
                await writer.drain()

                print("[DoT] DNS query forwarded successfully")

            except Exception as error:
                print(f"[Gateway Error] {error}")
                break

    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[DoT] Client disconnected: {peer}")


async def start_gateway(args):
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    tls_context.load_cert_chain(
        certfile=args.cert,
        keyfile=args.key
    )

    server = await asyncio.start_server(
        lambda reader, writer: handle_client(
            reader,
            writer,
            args.resolver,
            args.resolver_port
        ),
        host=args.host,
        port=args.port,
        ssl=tls_context
    )

    print("===================================")
    print("AIORI 3 DNSSEC DoT GATEWAY")
    print("===================================")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Unbound resolver: {args.resolver}:{args.resolver_port}")
    print("Transport: DNS-over-TLS")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=853)

    parser.add_argument("--resolver", default="127.0.0.1")
    parser.add_argument("--resolver-port", type=int, default=5335)

    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)

    args = parser.parse_args()

    asyncio.run(start_gateway(args))
