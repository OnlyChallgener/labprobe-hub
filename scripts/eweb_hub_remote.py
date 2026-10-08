"""Minimal SSH asset transport for eWeb; credentials are supplied by caller only."""
from __future__ import annotations
import hashlib
import logging
import shlex
import paramiko
from cryptography.hazmat.primitives import hashes

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def transport_factory(sock, **kwargs):
    transport = paramiko.Transport(sock, **kwargs)
    transport._key_info = dict(transport._key_info, **{"ssh-rsa": paramiko.RSAKey})
    transport.get_security_options().key_types = (*transport.get_security_options().key_types, "ssh-rsa")
    return transport

def connect(host, port, username, password, sock=None):
    paramiko.RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, sock=sock,
                   allow_agent=False, look_for_keys=False, timeout=8, banner_timeout=8,
                   auth_timeout=8, transport_factory=transport_factory)
    return client

def run(client, command, *, timeout=25, stdin=None, sudo_password=None):
    if sudo_password is not None:
        command = "sudo -S -p '' " + command
    stream, output, error = client.exec_command(command, timeout=timeout)
    if sudo_password is not None:
        stream.write(sudo_password + "\n")
        stream.flush()
    if stdin is not None:
        stream.channel.sendall(stdin)
    stream.channel.shutdown_write()
    value = output.read()
    failure = error.read()
    code = output.channel.recv_exit_status()
    if code:
        # Do not include arbitrary stdout/stderr: they can contain credentials.
        raise RuntimeError(f"Remote operation failed (exit {code})")
    return value

def read(client, path):
    return run(client, "cat " + shlex.quote(path))

def write(client, path, data, mode="644"):
    temporary = path + ".labprobe-stage"
    command = "umask 077; cat > " + shlex.quote(temporary)
    run(client, command, stdin=data)
    actual = read(client, temporary)
    if hashlib.sha256(actual).digest() != hashlib.sha256(data).digest():
        raise RuntimeError("Uploaded asset hash mismatch")
    run(client, "chmod " + mode + " " + shlex.quote(temporary) + " && mv " + shlex.quote(temporary) + " " + shlex.quote(path))
