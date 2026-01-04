#!/usr/bin/env python3
"""
VPN Server для Render.com с поддержкой health check
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
from aiohttp import web, ClientSession, TCPConnector
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
    
    async def websocket_handler(self, websocket, path):
        """Обработка WebSocket соединений"""
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
    
    async def health_check(self, request):
        """Обработчик health check запросов от Render.com"""
        return web.Response(text="OK", status=200)
    
    async def index(self, request):
        """Главная страница с информацией"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>VPN WebSocket Server</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                .status { padding: 10px; background: #e8f5e8; border-radius: 5px; }
                .code { background: #f4f4f4; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>VPN WebSocket Server</h1>
                <div class="status">
                    <p><strong>Статус:</strong> Сервер работает ✅</p>
                    <p><strong>WebSocket Endpoint:</strong> wss://%s/ws</p>
                    <p><strong>Health Check:</strong> <a href="/health">/health</a></p>
                </div>
                <h2>Пример использования:</h2>
                <div class="code">
                    <pre><code>
import asyncio
import websockets
import json

async def test_vpn():
    async with websockets.connect('wss://%s/ws') as websocket:
        # Ping запрос
        await websocket.send(json.dumps({'command': 'ping'}))
        response = await websocket.recv()
        print(f"Ping response: {response}")
        
        # HTTP запрос
        request = {
            'command': 'http_request',
            'method': 'GET',
            'url': 'https://api.ipify.org?format=json'
        }
        await websocket.send(json.dumps(request))
        response = await websocket.recv()
        print(f"HTTP response: {response}")

asyncio.run(test_vpn())
                    </code></pre>
                </div>
            </div>
        </body>
        </html>
        """ % (request.host, request.host)
        return web.Response(text=html, content_type='text/html')
    
    async def start(self):
        """Запуск сервера с поддержкой HTTP и WebSocket"""
        app = web.Application()
        
        # HTTP маршруты
        app.router.add_get('/', self.index)
        app.router.add_get('/health', self.health_check)
        
        # Создаем WebSocket сервер
        websocket_server = websockets.serve(
            self.websocket_handler,
            "0.0.0.0",
            int(os.getenv('PORT', 8080)),
            ping_interval=30,
            ping_timeout=60
        )
        
        # Запускаем WebSocket сервер
        server = await websocket_server
        
        # Запускаем HTTP сервер
        runner = web.AppRunner(app)
        await runner.setup()
        
        # Используем тот же порт для HTTP и WebSocket
        site = web.TCPSite(runner, "0.0.0.0", int(os.getenv('PORT', 8080)))
        await site.start()
        
        logging.info(f"Сервер запущен на порту {os.getenv('PORT', 8080)}")
        logging.info(f"HTTP: http://0.0.0.0:{os.getenv('PORT', 8080)}/")
        logging.info(f"WebSocket: ws://0.0.0.0:{os.getenv('PORT', 8080)}/ws")
        logging.info(f"Health check: http://0.0.0.0:{os.getenv('PORT', 8080)}/health")
        
        # Бесконечное ожидание
        await asyncio.Future()

if __name__ == "__main__":
    server = VPNServer()
    asyncio.run(server.start())
