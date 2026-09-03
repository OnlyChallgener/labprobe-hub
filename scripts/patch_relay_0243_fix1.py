from pathlib import Path

path = Path('labrelay/src/tcp_session_test.rs')
text = path.read_text(encoding='utf-8')

old = 'use tokio::net::{lookup_host, TcpSocket, TcpStream};'
new = 'use tokio::net::{lookup_host, TcpSocket};'
if text.count(old) != 1:
    raise SystemExit(f'tokio import: expected one match, got {text.count(old)}')
text = text.replace(old, new, 1)

old = '''                        match kind {
                            FailureKind::SourcePort => source_port_failures += 1,
                            FailureKind::FileDescriptor => fd_failures += 1,
                            FailureKind::Memory => memory_failures += 1,
                            FailureKind::Other => {}
                        }'''
new = '''                        match kind {
                            FailureKind::SourcePort => source_port_failures += 1,
                            FailureKind::SourcePortBusy => {}
                            FailureKind::FileDescriptor => fd_failures += 1,
                            FailureKind::Memory => memory_failures += 1,
                            FailureKind::Other => {}
                        }'''
if text.count(old) != 1:
    raise SystemExit(f'failure match: expected one match, got {text.count(old)}')
text = text.replace(old, new, 1)

path.write_text(text, encoding='utf-8')
