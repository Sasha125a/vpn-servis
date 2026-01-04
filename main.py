#!/usr/bin/env python3
"""
VPN Server для Render.com с WebSocket
"""

import asyncio
import websockets
import logging
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import aiohttp
from aiohttp import ClientSession, TCPConnector
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VPNServer:
    def __init__(self):
        self.clients = {}
        self.cipher_suite = None
        self.setup_encryption()
        
    def setup_encryption(self):
        """Настройка шифрования с использованием ключа"""
        password = b"vpn_secret_password_123"
        salt = b"vpn_salt_12345678"
        
        kdf = PBKDF2HMAC(
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
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(self.cipher_suite.encrypt(data)).decode()
    
    def decrypt(self, encrypted_data):
        """Расшифровка данных"""
        try:
            data = base64.b64decode(encrypted_data)
            return self.cipher_suite.decrypt(data)
        except:
            return b""
    
    async def handle_http_request(self, session, method, url, headers=None, data=None):
        """Обработка HTTP запросов через VPN"""
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_data = await response.read()
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': base64.b64encode(response_data).decode(),
                    'success': True
                }
        except Exception as e:
            logging.error(f"Ошибка HTTP запроса: {e}")
            return {
                'status': 500,
                'body': base64.b64encode(str(e).encode()).decode(),
                'success': False
            }
    
    async def handle_client(self, websocket, path):
        """Обработка подключения клиента через WebSocket"""
        client_address = websocket.remote_address
        logging.info(f"Новое WebSocket подключение от {client_address}")
        
        try:
            async with ClientSession(connector=TCPConnector(ssl=False)) as session:
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        command = data.get('command')
                        
                        if command == 'http_request':
                            # Обработка HTTP запроса
                            url = data['url']
                            method = data.get('method', 'GET')
                            headers = data.get('headers', {})
                            body_data = data.get('body')
                            
                            # Проверяем и декодируем тело если есть
                            if body_data:
                                try:
                                    body_data = base64.b64decode(body_data)
                                except:
                                    body_data = body_data.encode() if isinstance(body_data, str) else body_data
                            
                            logging.info(f"HTTP запрос: {method} {url}")
                            
                            response = await self.handle_http_request(
                                session, method, url, headers, body_data
                            )
                            
                            # Отправляем зашифрованный ответ
                            encrypted_response = self.encrypt(json.dumps(response))
                            await websocket.send(json.dumps({
                                'type': 'http_response',
                                'data': encrypted_response
                            }))
                            
                        elif command == 'ping':
                            # Проверка соединения
                            await websocket.send(json.dumps({
                                'type': 'pong',
                                'data': self.encrypt('pong')
                            }))
                            
                        elif command == 'test':
                            # Тестовый запрос
                            test_url = "http://httpbin.org/get"
                            response = await self.handle_http_request(session, 'GET', test_url)
                            encrypted_response = self.encrypt(json.dumps(response))
                            await websocket.send(json.dumps({
                                'type': 'test_response',
                                'data': encrypted_response
                            }))
                            
                    except json.JSONDecodeError:
                        logging.error("Неверный формат JSON")
                        await websocket.send(json.dumps({
                            'error': 'Invalid JSON format'
                        }))
                    except Exception as e:
                        logging.error(f"Ошибка обработки сообщения: {e}")
                        await websocket.send(json.dumps({
                            'error': str(e)
                        }))
                        
        except websockets.exceptions.ConnectionClosed:
            logging.info(f"Соединение с {client_address} закрыто")
        except Exception as e:
            logging.error(f"Ошибка соединения: {e}")
    
    async def start(self):
        """Запуск WebSocket сервера"""
        port = int(os.getenv('PORT', 8080))
        async with websockets.serve(
            self.handle_client, 
            "0.0.0.0", 
            port,
            ping_interval=30,
            ping_timeout=60
        ):
            logging.info(f"VPN WebSocket сервер запущен на порту {port}")
            logging.info(f"Сервер доступен по адресу: wss://vpn-servis.onrender.com")
            await asyncio.Future()  # Бесконечное ожидание

if __name__ == "__main__":
    server = VPNServer()
    asyncio.run(server.start())
