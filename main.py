#!/usr/bin/env python3
"""
VPN Server для Render.com
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
from aiohttp import web, ClientSession
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
    
    async def websocket_handler(self, request):
        """Обработка WebSocket соединений"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        client_address = request.remote
        logging.info(f"Новое WebSocket подключение от {client_address}")
        
        try:
            async with ClientSession() as session:
                async for msg in ws:
                    if msg.type == web.WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
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
                                await ws.send_json({
                                    'type': 'http_response',
                                    'data': encrypted_response
                                })
                                
                            elif command == 'ping':
                                # Проверка соединения
                                await ws.send_json({
                                    'type': 'pong',
                                    'data': self.encrypt('pong')
                                })
                                
                            elif command == 'test':
                                # Тестовый запрос
                                test_url = "http://httpbin.org/get"
                                response = await self.handle_http_request(session, 'GET', test_url)
                                encrypted_response = self.encrypt(json.dumps(response))
                                await ws.send_json({
                                    'type': 'test_response',
                                    'data': encrypted_response
                                })
                                
                        except json.JSONDecodeError:
                            logging.error("Неверный формат JSON")
                            await ws.send_json({
                                'error': 'Invalid JSON format'
                            })
                        except Exception as e:
                            logging.error(f"Ошибка обработки сообщения: {e}")
                            await ws.send_json({
                                'error': str(e)
                            })
                    elif msg.type == web.WSMsgType.ERROR:
                        logging.error(f'WebSocket ошибка: {ws.exception()}')
                        
        except Exception as e:
            logging.error(f"Ошибка соединения: {e}")
        finally:
            logging.info(f"Соединение с {client_address} закрыто")
        
        return ws
    
    async def health_check(self, request):
        """Обработчик health check запросов от Render.com"""
        return web.Response(text="OK", status=200)
    
    async def index(self, request):
        """Главная страница с информацией"""
        host = request.host
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VPN WebSocket Server</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .status {{ padding: 15px; background: #e8f5e8; border-radius: 5px; margin-bottom: 20px; }}
                .code {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                h1 {{ color: #333; }}
                .btn {{ display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
                .btn:hover {{ background: #0056b3; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 VPN WebSocket Server</h1>
                <div class="status">
                    <p><strong>Статус:</strong> Сервер работает ✅</p>
                    <p><strong>WebSocket Endpoint:</strong> <code>ws://{host}/ws</code></p>
                    <p><strong>Health Check:</strong> <a href="/health">/health</a></p>
                </div>
                
                <h2>📡 Тестирование</h2>
                <a class="btn" href="/test">Тест соединения</a>
                
                <h2>📚 Примеры использования</h2>
                <div class="code">
                    <h3>Python клиент:</h3>
                    <pre><code>
import asyncio
import websockets
import json

async def test_vpn():
    async with websockets.connect('ws://{host}/ws') as websocket:
        # Ping запрос
        await websocket.send(json.dumps({{'command': 'ping'}}))
        response = await websocket.recv()
        print(f"Ping response: {{response}}")
        
        # HTTP запрос через VPN
        request = {{
            'command': 'http_request',
            'method': 'GET',
            'url': 'https://api.ipify.org?format=json'
        }}
        await websocket.send(json.dumps(request))
        response = await websocket.recv()
        print(f"HTTP response: {{response}}")

asyncio.run(test_vpn())
                    </code></pre>
                    
                    <h3>JavaScript клиент:</h3>
                    <pre><code>
const ws = new WebSocket('ws://{host}/ws');

ws.onopen = () => {{
    console.log('Connected to VPN server');
    
    // Send ping
    ws.send(JSON.stringify({{command: 'ping'}}));
}};

ws.onmessage = (event) => {{
    console.log('Response:', event.data);
}};
                    </code></pre>
                </div>
                
                <h2>🔧 API Endpoints</h2>
                <ul>
                    <li><code>GET /</code> - Эта страница</li>
                    <li><code>GET /health</code> - Health check</li>
                    <li><code>GET /test</code> - Тест соединения</li>
                    <li><code>GET /ws</code> - WebSocket endpoint</li>
                </ul>
            </div>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def test_page(self, request):
        """Страница для тестирования WebSocket"""
        host = request.host
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Тест VPN соединения</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .container {{ max-width: 800px; margin: 0 auto; }}
                .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
                .success {{ background: #d4edda; color: #155724; }}
                .error {{ background: #f8d7da; color: #721c24; }}
                .btn {{ padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }}
                .btn:hover {{ background: #218838; }}
                #output {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Тест VPN соединения</h1>
                <button class="btn" onclick="testConnection()">Тестировать соединение</button>
                <button class="btn" onclick="getIP()">Получить IP через VPN</button>
                
                <div id="output"></div>
                
                <script>
                    let ws = null;
                    const output = document.getElementById('output');
                    
                    function log(message, type = 'info') {{
                        const status = document.createElement('div');
                        status.className = 'status ' + type;
                        status.textContent = message;
                        output.prepend(status);
                    }}
                    
                    function connectWebSocket() {{
                        if (ws && ws.readyState === WebSocket.OPEN) return ws;
                        
                        ws = new WebSocket('ws://{host}/ws');
                        
                        ws.onopen = () => {{
                            log('✅ WebSocket подключение установлено', 'success');
                        }};
                        
                        ws.onmessage = (event) => {{
                            try {{
                                const data = JSON.parse(event.data);
                                log('📥 Получен ответ: ' + JSON.stringify(data, null, 2));
                            }} catch (e) {{
                                log('📥 Получен ответ: ' + event.data);
                            }}
                        }};
                        
                        ws.onerror = (error) => {{
                            log('❌ WebSocket ошибка: ' + error, 'error');
                        }};
                        
                        ws.onclose = () => {{
                            log('🔌 WebSocket соединение закрыто');
                        }};
                        
                        return ws;
                    }}
                    
                    function testConnection() {{
                        try {{
                            const ws = connectWebSocket();
                            setTimeout(() => {{
                                ws.send(JSON.stringify({{command: 'ping'}}));
                                log('📤 Отправлен ping запрос');
                            }}, 1000);
                        }} catch (e) {{
                            log('❌ Ошибка: ' + e, 'error');
                        }}
                    }}
                    
                    function getIP() {{
                        try {{
                            const ws = connectWebSocket();
                            setTimeout(() => {{
                                const request = {{
                                    command: 'http_request',
                                    method: 'GET',
                                    url: 'https://api.ipify.org?format=json'
                                }};
                                ws.send(JSON.stringify(request));
                                log('📤 Отправлен запрос IP адреса');
                            }}, 1000);
                        }} catch (e) {{
                            log('❌ Ошибка: ' + e, 'error');
                        }}
                    }}
                </script>
            </div>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def start_server(self):
        """Запуск сервера"""
        app = web.Application()
        
        # HTTP маршруты
        app.router.add_get('/', self.index)
        app.router.add_get('/health', self.health_check)
        app.router.add_head('/health', self.health_check)  # Для HEAD запросов
        app.router.add_get('/test', self.test_page)
        app.router.add_get('/ws', self.websocket_handler)
        
        # Получаем порт из переменной окружения Render
        port = int(os.environ.get('PORT', 8080))
        
        # Запускаем сервер
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        
        logging.info(f"🚀 Сервер запущен на порту {port}")
        logging.info(f"🌐 HTTP: http://0.0.0.0:{port}/")
        logging.info(f"🔌 WebSocket: ws://0.0.0.0:{port}/ws")
        logging.info(f"🏥 Health check: http://0.0.0.0:{port}/health")
        logging.info(f"🛠️  Тест страница: http://0.0.0.0:{port}/test")
        
        # Бесконечное ожидание
        await asyncio.Future()

def main():
    server = VPNServer()
    
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logging.info("Сервер остановлен")
    except Exception as e:
        logging.error(f"Ошибка запуска сервера: {e}")

if __name__ == "__main__":
    main()
