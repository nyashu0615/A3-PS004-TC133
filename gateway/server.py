
import argparse
import asyncio
import ssl
import struct
import time

import dns.message
import dns.query
import dns.rcode


# ==============================================
# CONFIGURATION
# ==============================================

MAX_DNS_MESSAGE_SIZE = 4096
RESOLVER_TIMEOUT = 10


# ==============================================
# READ DNS-OVER-TLS FRAME
# RFC 7858: 2-byte length prefix + DNS message
# ==============================================

async def read_dns_frame(reader):

    header = await reader.readexactly(2)

    length = struct.unpack("!H", header)[0]

    if length < 12 or length > MAX_DNS_MESSAGE_SIZE:
        raise ValueError(f"Invalid DNS message length: {length}")

    return await reader.readexactly(length)


# ==============================================
# FORWARD DNS QUERY TO UNBOUND
# ==============================================

def forward_to_unbound(wire, resolver, resolver_port):

    query = dns.message.from_wire(wire)

    print(f"\n[Gateway] Query received: {query.question}")

    try:

        # First attempt: UDP
        response = dns.query.udp(
            query,
            resolver,
            port=resolver_port,
            timeout=RESOLVER_TIMEOUT
        )

        # TCP fallback if UDP response is truncated
        if response.flags & 0x0200:

            print("[Gateway] Truncated UDP response. Retrying using TCP.")

            response = dns.query.tcp(
                query,
                resolver,
                port=resolver_port,
                timeout=RESOLVER_TIMEOUT
            )

        print(
            "[Gateway] Resolver response:",
            dns.rcode.to_text(response.rcode())
        )

        return response.to_wire()

    except Exception as error:

        print(f"[Gateway] Resolver error: {error}")

        # Return a clearly logged synthetic SERVFAIL.
        # This represents a resolver failure, NOT proof
        # that DNSSEC validation rejected the domain.

        failure_response = dns.message.make_response(query)

        failure_response.set_rcode(dns.rcode.SERVFAIL)

        # Do not claim authenticated data on a synthetic response.
        failure_response.flags &= ~0x0020

        print("[Gateway] Returning synthetic SERVFAIL due to resolver failure.")

        return failure_response.to_wire()


# ==============================================
# HANDLE CONNECTED DoT CLIENT
# ==============================================

async def handle_client(
    reader,
    writer,
    resolver,
    resolver_port
):

    peer = writer.get_extra_info("peername")

    print(f"\n[DoT] Client connected: {peer}")

    try:

        while True:

            try:

                query_wire = await read_dns_frame(reader)

            except asyncio.IncompleteReadError:

                break

            except ValueError as error:

                print(f"[DoT] Invalid client frame: {error}")
                break

            try:

                loop = asyncio.get_running_loop()

                start_time = time.monotonic()

                response_wire = await loop.run_in_executor(
                    None,
                    forward_to_unbound,
                    query_wire,
                    resolver,
                    resolver_port
                )

                elapsed = time.monotonic() - start_time

                # RFC 7858 response framing
                response_frame = (
                    struct.pack("!H", len(response_wire))
                    + response_wire
                )

                writer.write(response_frame)

                await writer.drain()

                print(
                    f"[DoT] Response sent successfully "
                    f"({len(response_wire)} bytes, {elapsed:.3f}s)"
                )

            except Exception as error:

                print(f"[Gateway Error] {error}")
                break

    except Exception as error:

        print(f"[Client Error] {error}")

    finally:

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        print(f"[DoT] Client disconnected: {peer}")


# ==============================================
# START TLS GATEWAY
# ==============================================

async def start_gateway(args):

    tls_context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

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

    print("==========================================")
    print("       AIORI 3 DNSSEC DoT GATEWAY")
    print("==========================================")

    print(f"Listening address : {args.host}")
    print(f"Listening port    : {args.port}")
    print(f"Unbound resolver  : {args.resolver}")
    print(f"Resolver port     : {args.resolver_port}")
    print(f"Resolver timeout  : {RESOLVER_TIMEOUT} seconds")
    print("Transport         : DNS-over-TLS")
    print("TLS minimum       : TLS 1.2")

    print("==========================================")

    async with server:
        await server.serve_forever()


# ==============================================
# MAIN
# ==============================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="AIORI 3 DNSSEC Gateway"
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8853
    )

    parser.add_argument(
        "--resolver",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--resolver-port",
        type=int,
        default=5335
    )

    parser.add_argument(
        "--cert",
        required=True
    )

    parser.add_argument(
        "--key",
        required=True
    )

    args = parser.parse_args()

    asyncio.run(start_gateway(args))
