using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net;

// Hedef Sunucu 
string serverIp = "127.0.0.1";
int port = 514;

// Simülasyon için IP listesi 
string[] testIpleri = {
    // Küresel IP'ler
    "8.8.8.8", "45.33.32.156", "185.22.173.1", "1.1.1.1", "212.58.244.70",
    "176.234.226.126", // İstanbul 
    "94.54.191.150",   // Ankara 
    "78.160.12.30"     // İzmir
};

string[] users = { "admin", "misra", "root", "guest", "operator" };
string[] actions = { "LoginSuccess", "LoginFailed", "UnauthorizedAccess", "BruteForceAttempt" };

Random rnd = new Random();

while (true)
{
    Console.WriteLine("\n--- ORIANA SIEM | HİBRİT TEST SENDER ---");
    Console.WriteLine("1 - Manuel UDP Log Gönder");
    Console.WriteLine("2 - Manuel TCP Log Gönder (mTLS)");
    Console.WriteLine("3 - [HİBRİT SİMU] 15 Günlük Toplu Log (%50 UDP - %50 mTLS)");
    Console.WriteLine("0 - Çıkış");
    Console.Write("Seçiminiz: ");

    string secim = Console.ReadLine() ?? "";
    if (secim == "0") break;

    if (secim == "3")
    {
        Console.WriteLine("\n>>> 15 GÜNLÜK HİBRİT SİMÜLASYON BAŞLIYOR...");
        for (int i = 1; i <= 100; i++)
        {
            // Zaman simülasyonu
            int randomDaysBack = rnd.Next(0, 16);
            DateTime simDate = DateTime.Now.AddDays(-randomDaysBack)
                                          .AddHours(-rnd.Next(0, 24))
                                          .AddMinutes(-rnd.Next(0, 60));

            string simIp = testIpleri[rnd.Next(testIpleri.Length)];
            string simAction = actions[rnd.Next(actions.Length)];

            int severity;
            if (simAction.Contains("Unauthorized") || simAction.Contains("Critical") || simAction.Contains("Attack"))
            {
                severity = rnd.Next(9, 11); // En tehlikeli olaylar: 9 veya 10
            }
            else if (simAction.Contains("Failed") || simAction.Contains("Denied"))
            {
                severity = rnd.Next(7, 9);  // Yüksek riskli olaylar: 7 veya 8
            }
            else
            {
                severity = rnd.Next(1, 6);  // Normal/Düşük riskli olaylar: 1 ile 5 arası
            }

            // CEF Formatı - msgTime alanını doğru formatta ekliyoruz
            string bulkCef = $"CEF:0|OrianaTech|SecurityAI|1.0|100|{simAction}|{severity}|src={simIp} user={users[rnd.Next(users.Length)]} msgTime={simDate:yyyy-MM-ddTHH:mm:ss}";

            if (i % 2 == 0) SendUdp(bulkCef, serverIp, port);
            else _ = SendTls(bulkCef, serverIp, port);

            Thread.Sleep(25);
        }
        Console.WriteLine("\n>>> TAMAMLANDI!");
    }
    else if (secim == "1" || secim == "2")
    {
        // Manuel gönderilen log için IP kaynağı seçimi
        Console.Write("Seçilen IP Kaynağı (A: Yerel / B: Dünya): ");
        string ipSecim = Console.ReadLine()?.ToUpper() ?? "A";
        string aktifSrcIp = ipSecim == "B" ? testIpleri[rnd.Next(testIpleri.Length)] : "127.0.0.1";
        string manualCef = $"CEF:0|OrianaTech|Manual|1.0|100|LoginSuccess|3|src={aktifSrcIp} user=misra";

        if (secim == "1")
        {
            SendUdp(manualCef, serverIp, port);
            Console.WriteLine("Manuel UDP log gönderildi.");
        }
        else if (secim == "2")
        {
            await SendTls(manualCef, serverIp, port);
            Console.WriteLine("Manuel mTLS log gönderildi.");
        }
    }
} // while döngüsünün sonu

// --- YARDIMCI METOTLAR ---

static void SendUdp(string message, string ip, int port)
{
    try
    {
        using var udpClient = new UdpClient();
        byte[] data = Encoding.UTF8.GetBytes(message);
        udpClient.Send(data, data.Length, ip, port);
    }
    catch { }
}

static async Task SendTls(string message, string ip, int port)
{
    try
    {
        X509Certificate2 clientCert = new X509Certificate2("client.pfx", "1234");
        using var tcpClient = new TcpClient(ip, port);
        using var sslStream = new SslStream(tcpClient.GetStream(), false, (s, c, ch, e) => true);
        await sslStream.AuthenticateAsClientAsync("localhost", new X509Certificate2Collection(clientCert), SslProtocols.Tls12, false);
        if (sslStream.IsAuthenticated)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            await sslStream.WriteAsync(data, 0, data.Length);
        }
    }
    catch { }
}