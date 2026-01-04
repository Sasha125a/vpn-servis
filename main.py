#!/usr/bin/env python3
"""
VPN Server для Render.com
"""

import asyncio
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
                                
                            elif command == 'get_ip':
                                # Получение IP адреса
                                ip_url = "https://api.ipify.org?format=json"
                                response = await self.handle_http_request(session, 'GET', ip_url)
                                encrypted_response = self.encrypt(json.dumps(response))
                                await ws.send_json({
                                    'type': 'ip_response',
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
        # Определяем протокол для WebSocket
        ws_protocol = 'wss' if 'onrender.com' in host else 'ws'
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>VPN WebSocket Server</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        header {{ 
            text-align: center; 
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #f0f0f0;
        }}
        h1 {{ 
            color: #2c3e50; 
            font-size: 2.8rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{ 
            color: #7f8c8d; 
            font-size: 1.2rem;
            margin-bottom: 30px;
        }}
        .status-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            border-left: 5px solid #28a745;
        }}
        .endpoints {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .endpoint-card {{
            background: #fff;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border: 2px solid #e9ecef;
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .endpoint-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.2);
        }}
        .endpoint-card h3 {{
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .endpoint-card h3 i {{
            font-size: 1.5em;
        }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 12px 30px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: bold;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            margin: 10px 5px;
        }}
        .btn:hover {{
            transform: scale(1.05);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }}
        .btn-test {{
            background: linear-gradient(45deg, #28a745, #20c997);
        }}
        .test-section {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            margin-top: 40px;
        }}
        .test-output {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            min-height: 200px;
            margin-top: 20px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
        }}
        .log-entry {{
            padding: 5px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .log-success {{ color: #28a745; }}
        .log-error {{ color: #dc3545; }}
        .log-info {{ color: #17a2b8; }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #f0f0f0;
            color: #7f8c8d;
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 20px; }}
            h1 {{ font-size: 2rem; }}
            .endpoints {{ grid-template-columns: 1fr; }}
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-shield-alt"></i> VPN WebSocket Server</h1>
            <p class="subtitle">Безопасный доступ к интернету через зашифрованный WebSocket туннель</p>
        </header>
        
        <div class="status-card">
            <h2><i class="fas fa-check-circle"></i> Статус системы</h2>
            <p><strong>Статус:</strong> <span style="color: #28a745;">Сервер работает ✅</span></p>
            <p><strong>WebSocket Endpoint:</strong> <code>{ws_protocol}://{host}/ws</code></p>
            <p><strong>Health Check:</strong> <a href="/health" style="color: #667eea;">{host}/health</a></p>
        </div>
        
        <div class="endpoints">
            <div class="endpoint-card">
                <h3><i class="fas fa-globe"></i> WebSocket</h3>
                <p>Основной endpoint для VPN соединения:</p>
                <div class="code-block">
                    {ws_protocol}://{host}/ws
                </div>
                <button class="btn" onclick="testWebSocket()">
                    <i class="fas fa-plug"></i> Тест соединения
                </button>
            </div>
            
            <div class="endpoint-card">
                <h3><i class="fas fa-heartbeat"></i> Health Check</h3>
                <p>Проверка работоспособности сервера:</p>
                <div class="code-block">
                    GET {host}/health
                </div>
                <a href="/health" class="btn btn-test">
                    <i class="fas fa-stethoscope"></i> Проверить
                </a>
            </div>
            
            <div class="endpoint-card">
                <h3><i class="fas fa-code"></i> API Документация</h3>
                <p>Доступные команды WebSocket API:</p>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><code>{{"command": "ping"}}</code> - проверка связи</li>
                    <li><code>{{"command": "get_ip"}}</code> - получить IP</li>
                    <li><code>{{"command": "http_request", ...}}</code> - HTTP запрос</li>
                </ul>
            </div>
        </div>
        
        <div class="test-section">
            <h2><i class="fas fa-vial"></i> Тестирование в реальном времени</h2>
            <p>Проверьте работоспособность VPN соединения:</p>
            
            <div style="margin: 20px 0;">
                <button class="btn" onclick="sendCommand('ping')">
                    <i class="fas fa-satellite-dish"></i> Ping сервер
                </button>
                <button class="btn" onclick="sendCommand('get_ip')">
                    <i class="fas fa-map-marker-alt"></i> Получить IP
                </button>
                <button class="btn" onclick="sendCommand('http_request', 'https://httpbin.org/get')">
                    <i class="fas fa-external-link-alt"></i> Тест HTTP
                </button>
            </div>
            
            <div class="test-output" id="output">
                <div class="log-entry log-info">Готов к тестированию... Нажмите любую кнопку выше</div>
            </div>
        </div>
        
        <h2 style="margin-top: 40px;"><i class="fas fa-laptop-code"></i> Примеры кода</h2>
        
        <div class="code-block">
// Python клиент
import asyncio
import aiohttp
import json

async def test_vpn():
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect('{ws_protocol}://{host}/ws') as ws:
            # Ping
            await ws.send_str(json.dumps({{'command': 'ping'}}))
            msg = await ws.receive()
            print(f"Ping: {{json.loads(msg.data)}}")
            
            # Получить IP
            request = {{
                'command': 'http_request',
                'method': 'GET',
                'url': 'https://api.ipify.org?format=json'
            }}
            await ws.send_str(json.dumps(request))
            msg = await ws.receive()
            print(f"IP Response: {{json.loads(msg.data)}}")

asyncio.run(test_vpn())
        </div>
        
        <div class="code-block" style="margin-top: 20px;">
// JavaScript клиент
const ws = new WebSocket('{ws_protocol}://{host}/ws');

ws.onopen = () => {{
    console.log('Connected to VPN');
    
    // Отправка ping
    ws.send(JSON.stringify({{command: 'ping'}}));
}};

ws.onmessage = (event) => {{
    console.log('Response:', JSON.parse(event.data));
}};
        </div>
        
        <footer>
            <p>VPN WebSocket Server | Защищенное соединение | v1.0</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                <i class="fas fa-lock"></i> Все данные шифруются с помощью Fernet (AES-128)
            </p>
        </footer>
    </div>
    
    <script>
        let websocket = null;
        const output = document.getElementById('output');
        
        function addLog(message, type = 'info') {{
            const entry = document.createElement('div');
            entry.className = 'log-entry log-' + type;
            const time = new Date().toLocaleTimeString();
            entry.innerHTML = '[' + time + '] ' + message;
            output.appendChild(entry);
            output.scrollTop = output.scrollHeight;
        }}
        
        function connectWebSocket() {{
            if (websocket && websocket.readyState === WebSocket.OPEN) {{
                return websocket;
            }}
            
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';
            
            addLog('Подключаюсь к ' + wsUrl + '...', 'info');
            
            websocket = new WebSocket(wsUrl);
            
            websocket.onopen = function() {{
                addLog('✅ WebSocket подключение установлено', 'success');
            }};
            
            websocket.onmessage = function(event) {{
                try {{
                    const data = JSON.parse(event.data);
                    addLog('📥 Ответ: ' + JSON.stringify(data, null, 2), 'info');
                }} catch (e) {{
                    addLog('📥 Ответ: ' + event.data, 'info');
                }}
            }};
            
            websocket.onerror = function(error) {{
                addLog('❌ WebSocket ошибка', 'error');
            }};
            
            websocket.onclose = function() {{
                addLog('🔌 Соединение закрыто', 'info');
            }};
            
            return websocket;
        }}
        
        function sendCommand(command, url = null) {{
            try {{
                const ws = connectWebSocket();
                
                // Даем время на подключение
                setTimeout(function() {{
                    if (ws.readyState === WebSocket.OPEN) {{
                        let message;
                        
                        if (command === 'http_request' && url) {{
                            message = {{
                                command: 'http_request',
                                method: 'GET',
                                url: url
                            }};
                            addLog('📤 Отправка HTTP запроса: ' + url, 'info');
                        }} else if (command === 'get_ip') {{
                            message = {{
                                command: 'get_ip'
                            }};
                            addLog('📤 Запрос IP адреса...', 'info');
                        }} else {{
                            message = {{ command: command }};
                            addLog('📤 Отправка команды: ' + command, 'info');
                        }}
                        
                        ws.send(JSON.stringify(message));
                    }} else {{
                        addLog('❌ WebSocket не подключен. Пожалуйста, подождите...', 'error');
                    }}
                }}, 500);
                
            }} catch (error) {{
                addLog('❌ Ошибка: ' + error, 'error');
            }}
        }}
        
        function testWebSocket() {{
            addLog('🧪 Запуск теста WebSocket соединения...', 'info');
            sendCommand('ping');
            
            setTimeout(function() {{
                sendCommand('get_ip');
            }}, 1000);
            
            setTimeout(function() {{
                sendCommand('http_request', 'https://httpbin.org/get');
            }}, 2000);
        }}
        
        // Автоматическое подключение при загрузке страницы
        window.addEventListener('load', function() {{
            setTimeout(function() {{
                connectWebSocket();
            }}, 1000);
        }});
    </script>
</body>
</html>'''
        return web.Response(text=html, content_type='text/html')
    
    async def start_server(self):
        """Запуск сервера"""
        app = web.Application()
        
        # HTTP маршруты
        app.router.add_get('/', self.index)
        app.router.add_get('/health', self.health_check)
        
        # WebSocket маршрут
        app.router.add_get('/ws', self.websocket_handler)
        
        # Получаем порт из переменной окружения Render
        port = int(os.environ.get('PORT', 8080))
        
        # Запускаем сервер
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        
        logging.info(f"🚀 VPN сервер запущен!")
        logging.info(f"📡 Порт: {port}")
        logging.info(f"🌐 HTTP: http://0.0.0.0:{port}/")
        logging.info(f"🔌 WebSocket: ws://0.0.0.0:{port}/ws")
        logging.info(f"🏥 Health check: http://0.0.0.0:{port}/health")
        logging.info("=" * 50)
        logging.info("✅ Сервер готов к работе")
        logging.info("=" * 50)
        
        # Бесконечное ожидание
        await asyncio.Future()

def main():
    server = VPNServer()
    
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logging.info("\n🛑 Сервер остановлен пользователем")
    except Exception as e:
        logging.error(f"❌ Критическая ошибка запуска сервера: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
