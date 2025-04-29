using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace TerminalClient
{
    class TerminalClient
    {
        private TcpClient? _client;
        private NetworkStream? _stream;
        private readonly int _port = 2000;
        private bool _isConnected;
        private string? _currentIp;
        private readonly byte _delimiter = 0x00;
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private readonly ILogger<TerminalClient> _logger;

        public bool IsConnected => _isConnected;

        public TerminalClient(ILogger<TerminalClient> logger)
        {
            _isConnected = false;
            _currentIp = null;
            _logger = logger;
        }

        public async Task<bool> ConnectAsync(string ip)
        {
            _logger.LogInformation("Attempting connection to {Ip}:{Port}", ip, _port);
            if (!await _semaphore.WaitAsync(TimeSpan.FromSeconds(15)))
            {
                _logger.LogWarning("Semaphore timeout for {Ip}", ip);
                return false;
            }
            try
            {
                if (_isConnected && _currentIp == ip)
                {
                    _logger.LogInformation("Already connected to {Ip}:{Port}", ip, _port);
                    return true;
                }

                if (_isConnected && _currentIp != ip)
                {
                    _logger.LogInformation("Disconnecting from {CurrentIp} to connect to {Ip}", _currentIp, ip);
                    Disconnect();
                }

                if (!IPAddress.TryParse(ip, out _))
                {
                    _logger.LogError("Invalid IP address: {Ip}", ip);
                    return false;
                }

                try
                {
                    _client = new TcpClient();
                    _logger.LogInformation("Calling ConnectAsync for {Ip}:{Port}", ip, _port);
                    await _client.ConnectAsync(ip, _port);
                    _stream = _client.GetStream();
                    _isConnected = true;
                    _currentIp = ip;
                    _logger.LogInformation("Connected to terminal at {Ip}:{Port}", ip, _port);

                    bool handshakeSuccess = await PerformHandshakeAsync();
                    if (!handshakeSuccess)
                    {
                        _logger.LogError("Handshake failed for {Ip}", ip);
                        Disconnect();
                        return false;
                    }

                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Connection error to {Ip}", ip);
                    Disconnect();
                    return false;
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private async Task<bool> PerformHandshakeAsync()
        {
            string handshakeMsg = "{\"method\":\"PingDevice\",\"step\":0}";
            List<byte> data = new List<byte> { _delimiter };
            data.AddRange(Encoding.UTF8.GetBytes(handshakeMsg));
            data.Add(_delimiter);

            string response = await SendAndReceiveAsync(data.ToArray(), "Handshake");
            try
            {
                var jsonDoc = JsonDocument.Parse(response);
                bool error = jsonDoc.RootElement.GetProperty("error").GetBoolean();
                string responseCode = jsonDoc.RootElement.TryGetProperty("params", out var paramsObj) &&
                    paramsObj.TryGetProperty("responseCode", out var code) ? code.GetString() ?? "1000" : "1000";
                _logger.LogInformation("Handshake response: error={Error}, responseCode={ResponseCode}", error, responseCode);
                return !error && responseCode == "0000";
            }
            catch
            {
                _logger.LogError("Invalid handshake response format");
                return false;
            }
        }

        public async Task<string> ProcessCommandAsync(string jsonCommand, string ip)
        {
            _logger.LogInformation("Processing command for IP: {Ip}", ip);
            if (!await _semaphore.WaitAsync(TimeSpan.FromSeconds(15)))
            {
                _logger.LogWarning("Semaphore timeout for {Ip}", ip);
                return $"{{\"method\":\"{GetMethodFromCommand(jsonCommand)}\",\"step\":0,\"params\":{{\"responseCode\":\"1005\"}},\"error\":true,\"errorDescription\":\"Semaphore timeout\"}}";
            }
            try
            {
                if (!_isConnected || _currentIp != ip || _stream == null)
                {
                    bool connected = await ConnectAsync(ip);
                    if (!connected)
                    {
                        _logger.LogError("Failed to connect to terminal {Ip}", ip);
                        return $"{{\"method\":\"{GetMethodFromCommand(jsonCommand)}\",\"step\":0,\"params\":{{\"responseCode\":\"1004\"}},\"error\":true,\"errorDescription\":\"Not connected to terminal\"}}";
                    }
                }

                try
                {
                    string cleanedCommand = CleanCommand(jsonCommand);
                    List<byte> data = Encoding.UTF8.GetBytes(cleanedCommand).ToList();
                    data.Add(_delimiter);
                    byte[] buffer = data.ToArray();

                    string response = await SendAndReceiveAsync(buffer, "Command");
                    return EnsureProtocolCompliance(response, jsonCommand);
                }
                catch (TimeoutException)
                {
                    _logger.LogError("Timed out waiting for terminal response for {Ip}", ip);
                    return $"{{\"method\":\"{GetMethodFromCommand(jsonCommand)}\",\"step\":0,\"params\":{{\"responseCode\":\"1003\"}},\"error\":true,\"errorDescription\":\"Timed out waiting for terminal response\"}}";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing command for {Ip}", ip);
                    return $"{{\"method\":\"{GetMethodFromCommand(jsonCommand)}\",\"step\":0,\"params\":{{\"responseCode\":\"1000\"}},\"error\":true,\"errorDescription\":\"{ex.Message}\"}}";
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private string CleanCommand(string jsonCommand)
        {
            try
            {
                var jsonDoc = JsonDocument.Parse(jsonCommand);
                using var ms = new MemoryStream();
                using var writer = new Utf8JsonWriter(ms);
                writer.WriteStartObject();
                foreach (var prop in jsonDoc.RootElement.EnumerateObject())
                {
                    if (prop.Name != "terminalIp")
                    {
                        prop.WriteTo(writer);
                    }
                }
                writer.WriteEndObject();
                writer.Flush();
                return Encoding.UTF8.GetString(ms.ToArray());
            }
            catch
            {
                _logger.LogWarning("Failed to clean command: {Command}", jsonCommand);
                return jsonCommand;
            }
        }

        private async Task<string> SendAndReceiveAsync(byte[] data, string operation)
        {
            if (_stream == null)
            {
                throw new InvalidOperationException($"{operation} error: Stream is null");
            }

            try
            {
                await _stream.WriteAsync(data, 0, data.Length);
                string sentData = Encoding.UTF8.GetString(data.Where(x => x != _delimiter).ToArray());
                _logger.LogInformation("Sent {Operation}: {Data}", operation, sentData);

                return await ReceiveAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "{Operation} error", operation);
                throw;
            }
        }

        private async Task<string> ReceiveAsync()
        {
            if (_stream == null)
            {
                throw new InvalidOperationException("Stream is null");
            }

            byte[] buffer = new byte[4096];
            List<byte> receivedData = new List<byte>();
            using var cts = new CancellationTokenSource(_timeout);

            try
            {
                while (true)
                {
                    int bytesRead = await _stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                    if (bytesRead == 0)
                    {
                        throw new IOException("Connection closed by terminal");
                    }

                    for (int i = 0; i < bytesRead; i++)
                    {
                        if (buffer[i] == _delimiter)
                        {
                            string response = Encoding.UTF8.GetString(receivedData.ToArray());
                            if (!string.IsNullOrEmpty(response))
                            {
                                _logger.LogInformation("Received response: {Response}", response);
                                return response;
                            }
                            receivedData.Clear();
                            continue;
                        }
                        receivedData.Add(buffer[i]);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw new TimeoutException("Timed out waiting for terminal response");
            }
            catch (Exception ex)
            {
                throw new IOException($"Receive error: {ex.Message}");
            }
        }

        private string EnsureProtocolCompliance(string response, string originalCommand)
        {
            try
            {
                var jsonDoc = JsonDocument.Parse(response);
                bool error = jsonDoc.RootElement.GetProperty("error").GetBoolean();
                string? method = jsonDoc.RootElement.GetProperty("method").GetString();
                method = method ?? GetMethodFromCommand(originalCommand);
                int step = jsonDoc.RootElement.GetProperty("step").GetInt32();
                string responseCode = jsonDoc.RootElement.TryGetProperty("params", out var paramsObj) &&
                    paramsObj.TryGetProperty("responseCode", out var code) ? code.GetString() ?? "1000" : "1000";

                if (responseCode != "0000" && responseCode != "0010" && !error)
                {
                    return $"{{\"method\":\"{method}\",\"step\":{step},\"params\":{{\"responseCode\":\"{responseCode}\"}},\"error\":true,\"errorDescription\":\"Operation failed with response code {responseCode}\"}}";
                }
                return response;
            }
            catch
            {
                _logger.LogError("Invalid response format: {Response}", response);
                return $"{{\"method\":\"{GetMethodFromCommand(originalCommand)}\",\"step\":0,\"params\":{{\"responseCode\":\"1000\"}},\"error\":true,\"errorDescription\":\"Invalid response format\"}}";
            }
        }

        private string GetMethodFromCommand(string jsonCommand)
        {
            try
            {
                var jsonDoc = JsonDocument.Parse(jsonCommand);
                return jsonDoc.RootElement.GetProperty("method").GetString() ?? "Unknown";
            }
            catch
            {
                _logger.LogWarning("Failed to parse method from command: {Command}", jsonCommand);
                return "Unknown";
            }
        }

        public void Disconnect()
        {
            _semaphore.Wait();
            try
            {
                _stream?.Close();
                _client?.Close();
                _stream = null;
                _client = null;
                _isConnected = false;
                _logger.LogInformation("Disconnected from terminal {Ip}.", _currentIp ?? "unknown");
                _currentIp = null;
            }
            finally
            {
                _semaphore.Release();
            }
        }
    }

    class HttpServer
    {
        private readonly HttpListener _listener;
        private readonly TerminalClient _terminalClient;
        private readonly ILogger<HttpServer> _logger;
        private bool _isRunning;
        private readonly string _prefix = "http://localhost:8080/";

        public HttpServer(TerminalClient terminalClient, ILogger<HttpServer> logger)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(_prefix);
            _terminalClient = terminalClient;
            _logger = logger;
            _isRunning = false;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.Bind(new IPEndPoint(IPAddress.Any, 8080));
                }

                _listener.Start();
                _isRunning = true;
                _logger.LogInformation("HTTP server started at {Prefix}", _prefix);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start HTTP server");
                return;
            }

            while (_isRunning && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    HttpListenerContext context = await _listener.GetContextAsync();
                    _ = Task.Run(() => ProcessRequestAsync(context), cancellationToken);
                }
                catch (Exception ex) when (!_isRunning)
                {
                    _logger.LogInformation("HTTP listener stopped: {Message}", ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in HTTP listener");
                }
            }
        }

        private async Task ProcessRequestAsync(HttpListenerContext context)
        {
            _logger.LogInformation("Received request: {Method} {Url}", context.Request.HttpMethod, context.Request.Url);
            try
            {
                if (context.Request.HttpMethod == "POST" && 
                    (context.Request.Url?.AbsolutePath == "/api/terminal" || context.Request.Url?.AbsolutePath == "/api/terminal/"))
                {
                    if (context.Request.ContentType?.ToLower() != "application/json")
                    {
                        await SendErrorResponse(context, "Unknown", "Content-Type must be application/json", "1000", 415);
                        return;
                    }

                    using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                    {
                        string requestBody = await reader.ReadToEndAsync();
                        _logger.LogInformation("Request body: {Body}", requestBody);

                        string? terminalIp = null;
                        string? method = null;
                        try
                        {
                            var jsonDoc = JsonDocument.Parse(requestBody);
                            method = jsonDoc.RootElement.GetProperty("method").GetString();
                            if (jsonDoc.RootElement.TryGetProperty("terminalIp", out var ipProp))
                            {
                                terminalIp = ipProp.GetString()?.Trim();
                            }
                        }
                        catch
                        {
                            await SendErrorResponse(context, "Unknown", "Invalid JSON format", "1000", 400);
                            return;
                        }

                        if (string.IsNullOrEmpty(terminalIp))
                        {
                            await SendErrorResponse(context, method ?? "Unknown", "terminalIp is required in JSON body", "1000", 400);
                            return;
                        }

                        if (!IPAddress.TryParse(terminalIp, out _))
                        {
                            await SendErrorResponse(context, method ?? "Unknown", "Invalid terminalIp format", "1000", 400);
                            return;
                        }

                        _logger.LogInformation("Parsed terminalIp: {Ip}", terminalIp);
                        string response = await _terminalClient.ProcessCommandAsync(requestBody, terminalIp);
                        await SendResponse(context, response, 200);
                    }
                }
                else if (context.Request.Url?.AbsolutePath == "/test")
                {
                    _logger.LogInformation("Test endpoint called");
                    string response = "{\"status\":\"OK\"}";
                    await SendResponse(context, response, 200);
                }
                else
                {
                    _logger.LogWarning("Invalid request: {Method} {Url}", context.Request.HttpMethod, context.Request.Url);
                    await SendErrorResponse(context, "Unknown", "Not found", "1000", 404);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing request");
                await SendErrorResponse(context, "Unknown", $"Server error: {ex.Message}", "1000", 500);
            }
            finally
            {
                try
                {
                    context.Response.Close();
                    _logger.LogInformation("Response closed.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error closing response");
                }
            }
        }

        private async Task SendResponse(HttpListenerContext context, string response, int statusCode)
        {
            byte[] responseBytes = Encoding.UTF8.GetBytes(response);
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.ContentLength64 = responseBytes.Length;
            context.Response.StatusCode = statusCode;
            context.Response.KeepAlive = false;
            _logger.LogInformation("Sending response (length: {Length} bytes): {Response}", responseBytes.Length, response);
            await context.Response.OutputStream.WriteAsync(responseBytes, 0, responseBytes.Length);
            await context.Response.OutputStream.FlushAsync();
            _logger.LogInformation("Response sent.");
        }

        private async Task SendErrorResponse(HttpListenerContext context, string method, string errorDescription, string responseCode, int statusCode)
        {
            string response = $"{{\"method\":\"{method}\",\"step\":0,\"params\":{{\"responseCode\":\"{responseCode}\"}},\"error\":true,\"errorDescription\":\"{errorDescription}\"}}";
            await SendResponse(context, response, statusCode);
        }

        public void Stop()
        {
            if (_isRunning)
            {
                _isRunning = false;
                try
                {
                    _listener.Stop();
                    _listener.Close();
                    _logger.LogInformation("HTTP server stopped.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error stopping HTTP server");
                }
            }
        }
    }

    class TerminalService : BackgroundService
    {
        private readonly HttpServer _httpServer;
        private readonly TerminalClient _terminalClient;
        private readonly ILogger<TerminalService> _logger;

        public TerminalService(HttpServer httpServer, TerminalClient terminalClient, ILogger<TerminalService> logger)
        {
            _httpServer = httpServer;
            _terminalClient = terminalClient;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("TerminalService is starting.");
            await _httpServer.StartAsync(stoppingToken);
            _logger.LogInformation("TerminalService is stopping.");
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("TerminalService is stopping.");
            _httpServer.Stop();
            _terminalClient.Disconnect();
            await base.StopAsync(cancellationToken);
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.File("/var/log/terminalclient/terminalclient.log", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            try
            {
                var host = Host.CreateDefaultBuilder(args)
                    .UseSystemd()
                    .ConfigureServices((context, services) =>
                    {
                        services.AddHostedService<TerminalService>();
                        services.AddSingleton<TerminalClient>();
                        services.AddSingleton<HttpServer>();
                        services.AddLogging(builder =>
                        {
                            builder.AddSerilog();
                            builder.AddConsole();
                        });
                    })
                    .Build();

                // Тестовое подключение к 192.168.0.164
                using (var scope = host.Services.CreateScope())
                {
                    var terminalClient = scope.ServiceProvider.GetRequiredService<TerminalClient>();
                    Log.Information("Testing connection to 192.168.0.164...");
                    bool connected = await terminalClient.ConnectAsync("192.168.0.164");
                    if (!connected)
                    {
                        Log.Information("Initial connection to 192.168.0.164 failed. Continuing...");
                    }
                    else
                    {
                        Log.Information("Initial connection to 192.168.0.164 successful.");
                    }
                }

                await host.RunAsync();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application failed to start");
                throw;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}