using SIEM.Core.Helpers;
using SIEM.Core.Models;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

Console.WriteLine("--- SIEM Log Scanner Başlatıldı (mTLS & UDP MOD) ---");

int port = 514;
var mongoHelper = new MongoDbHelper();
var database = mongoHelper.GetDatabase();

// 1. Yardımcı Servisleri Başlat
var engine = new CorrelationEngine(database);
var geoService = new GeoLocationService(); // **GeoIP servisi
Console.WriteLine(">>> SIEM Korelasyon Motoru ve GeoIP Servisi Hazır.");

// Analiz döngüsünü arka planda başlatıyoruz
_ = Task.Run(async () =>
{
    while (true)
    {
        try
        {
            await engine.RunAnalysisAsync();
        } 
        catch (Exception ex)
        {
            Console.WriteLine($"[KORELASYON HATASI] {ex.Message}");
        }
        await Task.Delay(10000);
    }
});

// 2. Sunucu Sertifikasını Yükle
X509Certificate2 serverCertificate = new X509Certificate2("server.pfx", "1234");

// UDP ve TCP dinleyicilerini başlat
_ = Task.Run(() => StartUdpListener(port));
_ = Task.Run(() => StartTcpListener(port, serverCertificate));

Console.WriteLine($"Sistem UDP ve TCP (mTLS) {port} üzerinden dinlemede.");
Console.WriteLine("Kapatmak için bir tuşa basın...");
Console.ReadLine();

//  METOTLAR 

async Task StartUdpListener(int port)
{
    using var udpServer = new UdpClient(port);
    var remoteEP = new IPEndPoint(IPAddress.Any, port);

    while (true)
    {
        UdpReceiveResult result = await udpServer.ReceiveAsync();
        byte[] data = result.Buffer;
        string message = Encoding.UTF8.GetString(data);
        await ProcessLog(message, "UDP", result.RemoteEndPoint.Address.ToString());
    }
}

async Task StartTcpListener(int port, X509Certificate2 cert)
{
    TcpListener tcpServer = new TcpListener(IPAddress.Any, port);
    tcpServer.Start();

    while (true)
    {
        try
        {
            TcpClient client = await tcpServer.AcceptTcpClientAsync();
            _ = Task.Run(() => HandleTcpClient(client, cert));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"TCP Kabul Hatası: {ex.Message}");
        }
    }
}

async Task HandleTcpClient(TcpClient client, X509Certificate2 cert)
{
    string clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "Bilinmiyor";
    SslStream sslStream = new SslStream(client.GetStream(), false,
        new RemoteCertificateValidationCallback(ValidateClientCertificate));

    try
    {
        await sslStream.AuthenticateAsServerAsync(cert,
            clientCertificateRequired: true,
            enabledSslProtocols: SslProtocols.Tls12,
            checkCertificateRevocation: false);

        byte[] buffer = new byte[2048];
        int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);

        if (bytesRead > 0)
        {
            string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            await ProcessLog(message, "TCP-mTLS", clientIp);
        }
    }
    catch (AuthenticationException ex)
    {
        Console.WriteLine($"[GÜVENLİK UYARISI] Sertifikasız veya geçersiz bağlantı reddedildi: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Bağlantı hatası: {ex.Message}");
    }
    finally
    {
        sslStream.Close();
        client.Close();
    }
}

bool ValidateClientCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    return true;
}

async Task ProcessLog(string message, string protocol, string ip)
{
    try
    {
        // Bu blok, mesajda 'CEF:' ifadesini bulur ve öncesini atarak parser'ın bozulmasını engeller.
        int cefIndex = message.IndexOf("CEF:");
        if (cefIndex != -1)
        {
            message = message.Substring(cefIndex);
        }

        // 1. Logu Ayrıştır (Artık temizlenmiş mesajı kullanıyoruz)
        var parsedLog = CefParser.Parse(message, ip, protocol);

        // API'ye sormak için gerçek saldırgan IP'sini seçiyoruz.
        // Eğer CEF mesajının içinde 'src' varsa onu al, yoksa fiziksel bağlantı IP'sini kullan.
        string targetIp = "";

        if (parsedLog.Extensions != null && parsedLog.Extensions.ContainsKey("src"))
        {
            targetIp = parsedLog.Extensions["src"]; // TestSender'dan gelen simülasyon IP'si
        }
        else
        {
            targetIp = parsedLog.SourceIp; // Eğer src yoksa mecbur fiziksel IP (127.0.0.1)
        }

        // 2. GeoIP Kontrolü (targetIp üzerinden yapılıyor)
        if (!string.IsNullOrEmpty(targetIp) && targetIp != "127.0.0.1" && targetIp != "::1" && targetIp != "localhost")
        {
            // 1. Gerçek GeoIP sorgusunu yapıyoruz
            var (country, city) = await geoService.GetLocationAsync(targetIp);

            // 2. ANALİZ MODU: Türkiye verisini metropollere normalize etme
            if (country == "Türkiye" || country == "Turkey")
            {
                // Gelen şehri kontrol et ve 3 metropolden birine ata
                if (city == "Aydin" || city == "Izmir" || city == "Manisa")
                    city = "Izmir";
                else if (city == "Konya" || city == "Ankara" || city == "Eskisehir")
                    city = "Ankara";
                else
                    city = "Istanbul"; 
            }

            parsedLog.Country = country;
            parsedLog.City = city;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[GEO SUCCESS] IP: {targetIp} -> {city}, {country}");
            Console.ResetColor();
        }
        else
        {
            // Yerel ağ tespiti korunuyor
            parsedLog.Country = "Yerel Ağ";
            parsedLog.City = "Dahili";
        }

        // 3. Veritabanına Kaydet
        await mongoHelper.SaveLogAsync(parsedLog);

        // 4. Ekrana Bilgi Bas
        Console.WriteLine($"------------------------------------------");
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] >>> [{protocol}] Log Kaydedildi!");
        Console.WriteLine($"Kaynak IP (CEF): {targetIp}");
        Console.WriteLine($"Konum: {parsedLog.City}, {parsedLog.Country}");
        Console.WriteLine($"------------------------------------------");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Log işlenirken hata oluştu: {ex.Message}");
    }
}