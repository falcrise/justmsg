import asyncio
import getpass
from crypto_utils import derive_key, encrypt, decrypt

async def read_from_network(reader, key):
    """Reads and decrypts messages from the network."""
    while True:
        try:
            data = await reader.read(4096)
            if not data:
                print("\nServer closed the connection.")
                break
            
            decrypted_message = decrypt(key, data)
            if decrypted_message:
                print(f"\rReceived: {decrypted_message}\nEnter message: ", end="")

        except (asyncio.IncompleteReadError, ConnectionResetError):
            print("\nConnection to the server was lost.")
            break
    # This will cause the main loop to terminate
    raise ConnectionResetError

async def read_from_stdin(writer, key):
    """Reads messages from stdin and sends them over the network."""
    loop = asyncio.get_running_loop()
    while True:
        message = await loop.run_in_executor(None, lambda: input("Enter message: "))
        if not writer.is_closing():
            try:
                encrypted_message = encrypt(key, message)
                writer.write(encrypted_message)
                await writer.drain()
            except ConnectionResetError:
                print("Connection closed. Cannot send message.")
                break
        else:
            print("Writer is closed.")
            break

async def main():
    server_ip = input("Enter server IP address: ")
    room_name = input("Enter room name: ")
    passkey = getpass.getpass("Enter passkey: ")

    try:
        reader, writer = await asyncio.open_connection(server_ip, 8888)
    except (ConnectionRefusedError, OSError) as e:
        print(f"Could not connect to the server: {e}")
        return

    # Send room and passkey for validation
    writer.write(f"{room_name}\n".encode())
    await writer.drain()
    writer.write(f"{passkey}\n".encode())
    await writer.drain()

    response = await reader.read(1024)
    if response.decode().strip() != "OK":
        print("Server rejected connection. Check room name and passkey.")
        writer.close()
        await writer.wait_closed()
        return

    print("Connection successful. You can now send messages.")
    session_key = derive_key(room_name, passkey)

    # Start communication tasks
    network_task = asyncio.create_task(read_from_network(reader, session_key))
    stdin_task = asyncio.create_task(read_from_stdin(writer, session_key))

    try:
        await asyncio.gather(network_task, stdin_task)
    except ConnectionResetError:
        print("Disconnected from server.")
    finally:
        # Ensure tasks are cancelled before closing
        network_task.cancel()
        stdin_task.cancel()
        await asyncio.sleep(0.1) # Give tasks a moment to cancel
        writer.close()
        await writer.wait_closed()
        print("Connection closed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient shutting down.")
