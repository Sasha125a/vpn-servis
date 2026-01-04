#!/usr/bin/env python3
"""
VPN Server с шифрованием трафика
Запуск: python3 server.py
"""

import socket
import threading
import ssl
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VPNServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.clients = {}
        self.cipher_suite = None
        self.setup_encryption()
        
    def setup_encryption(self):
        """Настройка шифрования с использованием ключа"""
        # В реальном приложении ключ должен храниться безопасно
        password = b"vpn_secret_password_123"
        salt = b"vpn_salt_12345678"
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher_suite = Fernet(key)
        logging.info("Шифрование настроено")
    
    def encrypt(self, data):
        """Шифрование данных"""
        return self.cipher_suite.encrypt(data)
    
    def decrypt(self, data):
        """Расшифровка данных"""
        return self.cipher_suite.decrypt(data)
    
    def handle_client(self, client_socket, client_address):
        """Обработка подключения клиента"""
        logging.info(f"Новое подключение от {client_address}")
        
        try:
            # Получаем и расшифровываем целевой адрес от клиента
            target_info = client_socket.recv(1024)
            if not target_info:
                return
                
            target_info = self.decrypt(target_info)
            target_host, target_port = target_info.decode().split(':')
            target_port = int(target_port)
            
            logging.info(f"Клиент {client_address} запрашивает подключение к {target_host}:{target_port}")
            
            # Создаем соединение с целевым сервером
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            
            try:
                target_socket.connect((target_host, target_port))
            except Exception as e:
                logging.error(f"Не удалось подключиться к {target_host}:{target_port} - {e}")
                client_socket.close()
                return
            
            # Уведомляем клиент об успешном подключении
            client_socket.send(self.encrypt(b"CONNECTED"))
            
            # Начинаем маршрутизацию трафика
            self.route_traffic(client_socket, target_socket)
            
        except Exception as e:
            logging.error(f"Ошибка обработки клиента {client_address}: {e}")
        finally:
            client_socket.close()
            logging.info(f"Соединение с {client_address} закрыто")
    
    def route_traffic(self, client_socket, target_socket):
        """Маршрутизация трафика между клиентом и целевым сервером"""
        sockets = [client_socket, target_socket]
        
        while True:
            try:
                # Используем select для мониторинга сокетов
                import select
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
                
                for sock in readable:
                    if sock is client_socket:
                        # Данные от клиента -> целевой сервер
                        data = sock.recv(4096)
                        if not data:
                            return
                        try:
                            decrypted_data = self.decrypt(data)
                            target_socket.send(decrypted_data)
                        except:
                            continue
                            
                    elif sock is target_socket:
                        # Данные от целевого сервера -> клиент
                        data = sock.recv(4096)
                        if not data:
                            return
                        encrypted_data = self.encrypt(data)
                        client_socket.send(encrypted_data)
                
                for sock in exceptional:
                    return
                    
            except Exception as e:
                logging.error(f"Ошибка маршрутизации: {e}")
                break
    
    def start(self):
        """Запуск VPN сервера"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logging.info(f"VPN сервер запущен на {self.host}:{self.port}")
        logging.info("Ожидание подключений...")
        
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logging.info("Остановка сервера...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = VPNServer()
    server.start()
