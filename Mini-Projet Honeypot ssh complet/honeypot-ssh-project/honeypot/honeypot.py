#!/usr/bin/env python3
import socket
import threading
import paramiko
import json
import time
import subprocess
from datetime import datetime
import os
import sys

# Configuration
HOST = '0.0.0.0'
PORT = 2222
LOG_FILE = '/var/log/honeypot/honeypot.log'
RSA_KEY_FILE = '/tmp/honeypot_rsa_key'

# Dictionnaire pour détecter le brute-force
brute_force_tracker = {}
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = 60

class SSHServerHandler(paramiko.ServerInterface):
    """Gère les tentatives de connexion SSH"""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None
    
    def check_auth_password(self, username, password):
        """ACCEPTE TOUTES LES CONNEXIONS (honeypot)"""
        self.username = username
        self.password = password
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'login_attempt',
            'ip': self.client_ip,
            'username': username,
            'password': password,
            'auth_method': 'password',
            'success': True  
        }
        log_event(log_entry)
        
        # Détection brute-force
        detect_brute_force(self.client_ip)
        
        # ACCEPTER la connexion (simulation de serveur compromis)
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        """Accepte aussi les clés publiques"""
        self.username = username
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'login_attempt',
            'ip': self.client_ip,
            'username': username,
            'key_type': key.get_name(),
            'auth_method': 'publickey',
            'success': True
        }
        log_event(log_entry)
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        """Annonce les méthodes acceptées"""
        return 'password,publickey'
    
    def check_channel_request(self, kind, chanid):
        """Accepte les demandes de canal"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Accepte les demandes de shell"""
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Accepte les demandes de pseudo-terminal"""
        return True
    
    def check_channel_exec_request(self, channel, command):
        """Accepte les demandes d'exécution de commande"""
        command_str = command.decode('utf-8', errors='ignore')
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'command_execution',
            'ip': self.client_ip,
            'username': self.username,
            'command': command_str
        }
        log_event(log_entry)
        return True


def log_event(event_data):
    """Enregistre un événement au format JSON"""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(event_data) + '\n')
            f.flush()
        print(f"[LOG] {event_data['event_type']} from {event_data.get('ip', 'system')}")
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}", file=sys.stderr)


def detect_brute_force(ip):
    """Détecte les tentatives de brute-force"""
    current_time = time.time()
    
    if ip not in brute_force_tracker:
        brute_force_tracker[ip] = []
    
    brute_force_tracker[ip].append(current_time)
    brute_force_tracker[ip] = [
        t for t in brute_force_tracker[ip] 
        if current_time - t < BRUTE_FORCE_WINDOW
    ]
    
    if len(brute_force_tracker[ip]) >= BRUTE_FORCE_THRESHOLD:
        alert_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'brute_force_alert',
            'ip': ip,
            'attempts': len(brute_force_tracker[ip]),
            'time_window': BRUTE_FORCE_WINDOW
        }
        log_event(alert_data)
        print(f"[ALERT] Brute-force detected from {ip}!")
        brute_force_tracker[ip] = []


def generate_rsa_key():
    """Génère une clé RSA pour le serveur SSH"""
    if not os.path.exists(RSA_KEY_FILE):
        print("[INFO] Generating RSA key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(RSA_KEY_FILE)
        print(f"[INFO] RSA key saved to {RSA_KEY_FILE}")
    return paramiko.RSAKey.from_private_key_file(RSA_KEY_FILE)


def handle_shell(channel, client_ip, username):
    """Gère le shell interactif - CAPTURE LES COMMANDES"""
    channel.send(b"\r\n")
    channel.send(b"Welcome to Ubuntu 24.04 LTS\r\n")
    channel.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {client_ip}\r\n".encode())
    channel.send(f"{username}@honeypot:~$ ".encode())
    
    command_buffer = ""
    
    try:
        while True:
            char = channel.recv(1)
            if not char:
                break
            
            char = char.decode('utf-8', errors='ignore')
            
           # Enter pressé
            if char == '\r' or char == '\n':
                if command_buffer.strip():
                    command = command_buffer.strip()
                    # Logger la commande
                    log_entry = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'event_type': 'command_execution',
                        'ip': client_ip,
                        'username': username,
                        'command': command
                    }
                    log_event(log_entry)
                    
                    # Gérer les commandes spéciales
                    if command.lower() in ['exit', 'logout', 'quit']:
                        channel.send(b"\r\nlogout\r\n")
                        log_entry = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'session_closed',
                            'ip': client_ip,
                            'username': username,
                            'reason': 'user_exit'
                        }
                        log_event(log_entry)
                        break  # Sort de la boucle while
                    
                    # Exécuter la commande (AppArmor va bloquer les dangereuses)
                    channel.send(b"\r\n")
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            timeout=5,
                            text=True
                        )
                        
                        output = result.stdout + result.stderr
                        if output:
                            channel.send(output.encode('utf-8', errors='ignore'))
                        
                        # Logger le résultat
                        log_entry = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'command_result',
                            'ip': client_ip,
                            'username': username,
                            'command': command,
                            'output': output[:500],  # Limiter la taille
                            'exit_code': result.returncode
                        }
                        log_event(log_entry)
                        
                    except subprocess.TimeoutExpired:
                        channel.send(b"Command timeout\r\n")
                    except Exception as e:
                        channel.send(f"Error: {str(e)}\r\n".encode())
                    
                    channel.send(f"{username}@honeypot:~$ ".encode())
                    command_buffer = ""
                else:
                    channel.send(b"\r\n")
                    channel.send(f"{username}@honeypot:~$ ".encode())
                    command_buffer = ""
            
            # Backspace
            elif char == '\x7f':
                if command_buffer:
                    command_buffer = command_buffer[:-1]
                    channel.send(b'\x08 \x08')
            
            # Ctrl+C
            elif char == '\x03':
                channel.send(b"^C\r\n")
                channel.send(f"{username}@honeypot:~$ ".encode())
                command_buffer = ""
            
            # Ctrl+D (exit)
            elif char == '\x04':
                channel.send(b"\r\nlogout\r\n")
                break
            
            # Caractère normal
            else:
                command_buffer += char
                channel.send(char.encode())
    
    except Exception as e:
        print(f"[ERROR] Shell error: {e}")
    finally:
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'session_closed',
            'ip': client_ip,
            'username': username
        }
        log_event(log_entry)


def handle_client(client_socket, client_address):
    """Gère une connexion client SSH"""
    client_ip = client_address[0]
    print(f"[INFO] Connection from {client_ip}:{client_address[1]}")
    
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(generate_rsa_key())
        
        server = SSHServerHandler(client_ip)
        transport.start_server(server=server)
        
        channel = transport.accept(20)
        
        if channel is None:
            print(f"[INFO] No channel from {client_ip}")
            return
        
        # Attendre la demande de shell
        server.event.wait(10)
        
        if not server.event.is_set():
            print(f"[INFO] No shell request from {client_ip}")
            channel.close()
            return
        
        # Démarrer le shell interactif
        print(f"[INFO] Starting shell for {server.username}@{client_ip}")
        handle_shell(channel, client_ip, server.username)
        
        channel.close()
        
    except paramiko.SSHException as e:
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'connection_error',
            'ip': client_ip,
            'error': str(e)
        }
        log_event(log_entry)
    except Exception as e:
        print(f"[ERROR] Exception handling client {client_ip}: {e}")
    finally:
        try:
            if transport:
                transport.close()
        except:
            pass
        client_socket.close()


def start_honeypot():
    """Démarre le serveur honeypot SSH"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    print(f"[INFO] SSH Honeypot starting...")
    
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': 'honeypot_started',
        'honeypot_host': HOST,
        'port': PORT,
        'seccomp_mode': 'docker_profile'
    }
    log_event(log_entry)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    
    print(f"[INFO] SSH Honeypot started on {HOST}:{PORT}")
    print(f"[INFO] Logs: {LOG_FILE}")
    print(f"[INFO] ACCEPTING ALL CONNECTIONS - Interactive Shell Enabled")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down honeypot...")
    finally:
        server_socket.close()
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'honeypot_stopped'
        }
        log_event(log_entry)


if __name__ == '__main__':
    start_honeypot()
