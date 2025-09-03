import asyncio
import configparser
import os
import sys
from crypto_utils import derive_key, encrypt, decrypt

connections = {}

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection attempt from {addr}")
    room_name = None  # Define room_name here to be accessible in finally block
    stdin_task = None
    network_task = None

    try:
        # Room and passkey validation - Read line by line
        room_data = await reader.readline()
        pass_data = await reader.readline()

        # Handle case where client disconnects early
        if not room_data or not pass_data:
            print("Client disconnected before sending credentials.")
            return

        room_name = room_data.decode().strip()
        passkey = pass_data.decode().strip()

        if room_name not in connections or connections[room_name].get('writer') is not None:
            print(f"Room is invalid or already occupied.")
            writer.close()
            await writer.wait_closed()
            return

        server_passkey = connections[room_name]['passkey']
        if passkey != server_passkey:
            print("Passkey mismatch. Closing connection.")
            writer.close()
            await writer.wait_closed()
            return
        
        session_key = connections[room_name]['key']
        connections[room_name]['writer'] = writer
        
        writer.write(b"OK\n")
        await writer.drain()
        
        print(f"Client {addr} joined room. Chat session active. Type messages and press Enter.")
        print("---")

        # Create concurrent tasks for reading from network and stdin
        network_task = asyncio.create_task(read_from_network(reader, session_key))
        stdin_task = asyncio.create_task(read_from_stdin(writer, session_key))

        # Wait for either task to complete
        await asyncio.gather(network_task, stdin_task)

    except (asyncio.IncompleteReadError, ConnectionResetError) as e:
        print(f"Client disconnected: {e}")
    finally:
        print("---")
        print("Session ended.")
        if stdin_task and not stdin_task.done():
            stdin_task.cancel()
        if network_task and not network_task.done():
            network_task.cancel()

        if room_name and room_name in connections:
            # Reset the room to be available for a new client
            connections[room_name]['writer'] = None
            print(f"Room is now inactive and ready for a new client.")
        
        if writer and not writer.is_closing():
            writer.close()
            await writer.wait_closed()

async def read_from_network(reader, key):
    """Reads and decrypts messages from the network."""
    while True:
        try:
            data = await reader.read(4096)
            if not data:
                break
            
            decrypted_message = decrypt(key, data)
            if decrypted_message:
                print(f"Received: {decrypted_message}")

        except (asyncio.IncompleteReadError, ConnectionResetError):
            break
    print("\nNetwork stream closed by client.")

async def read_from_stdin(writer, key):
    """Reads messages from the local terminal (stdin) and sends them."""
    loop = asyncio.get_event_loop()
    while True:
        try:
            message = await loop.run_in_executor(None, sys.stdin.readline)
            message = message.strip()
            if message:
                encrypted_message = encrypt(key, message)
                writer.write(encrypted_message)
                await writer.drain()
        except Exception:
            break
    print("\nLocal input stream closed.")


async def main():
    # Get the absolute path to the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')

    # Read configuration from file
    config = configparser.ConfigParser()
    config.read(config_path)

    # Check if the config was read successfully
    if not config.has_section('server'):
        print(f"Error: Could not find 'server' section in {config_path}. Please check the config file.")
        return

    room_name = config['server']['room_name']
    passkey = config['server']['passkey']
    host = config['server']['host']
    port = int(config['server']['port'])

    print("Configuration loaded successfully.")

    session_key = derive_key(room_name, passkey)
    # The room is initialized but has no active writer
    connections[room_name] = {'passkey': passkey, 'key': session_key, 'writer': None}
    
    server = await asyncio.start_server(
        handle_client, host, port)

    addr = server.sockets[0].getsockname()
    print(f'Server listening on {addr}')
    print("Room is ready. Waiting for a client to connect...")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down.")
