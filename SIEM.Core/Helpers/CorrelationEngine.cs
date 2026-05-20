using MongoDB.Bson;
using MongoDB.Driver;
using Newtonsoft.Json;
using SIEM.Core.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SIEM.Core.Helpers
{
    public class CorrelationEngine
    {
        private readonly IMongoCollection<LogModel> _logCollection;
        private List<RuleModel> _rules = new();

     
        // IP bazlı son alarm zamanını tutan sözlük
        private static Dictionary<string, DateTime> _lastAlarmTimes = new Dictionary<string, DateTime>();

        public CorrelationEngine(IMongoDatabase database)
        {
            _logCollection = database.GetCollection<LogModel>("Logs");
            LoadRules();
        }

        // 1. JSON dosyasından kuralları yükle
        private void LoadRules()
        {
            try
            {
                string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules.json");
                if (File.Exists(jsonPath))
                {
                    string jsonContent = File.ReadAllText(jsonPath);
                    var deserializedResult = JsonConvert.DeserializeObject<List<RuleModel>>(jsonContent);

                    if (deserializedResult != null)
                    {
                        _rules = deserializedResult;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HATA] Kurallar yüklenemedi: {ex.Message}");
            }
        }

        // 2. Korelasyon analizini başlat
        public async Task RunAnalysisAsync()
        {
            Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] Korelasyon Motoru Çalışıyor...");

            foreach (var rule in _rules)
            {
                var timeLimit = DateTime.UtcNow.AddMinutes(-rule.TimeWindowMinutes);
                //AGGREGATION PIPELINE:
                //şu son 5 dakika içindeki logları getir,
                //bunları kaynak IP'lerine göre grupla,
                //her IP'nin kaç deneme yaptığını say, 
                //sadece 5'ten fazla denemesi olanları bana göster
                var results = await _logCollection.Aggregate()
                    .Match(l => l.LogTime >= timeLimit)
                    .Group(
                        l => l.Extensions["src"],
                        g => new
                        {
                            Key = g.Key,
                            Count = g.Count()
                        }
                    )
                    .Match(g => g.Count >= rule.Threshold)
                    .ToListAsync();

                foreach (var alert in results)
                {
                    // Aggregation sonucundan gelen IP adresi
                    string sourceIp = alert.Key;

                    // --- COOLDOWN (BEKLEME SÜRESİ) KONTROLÜ ---
                    if (_lastAlarmTimes.TryGetValue(sourceIp, out DateTime lastTime))
                    {
                        // Eğer son alarm üzerinden 5 dakika geçmediyse bu IP için alarm üretme
                        if ((DateTime.UtcNow - lastTime).TotalMinutes < 5)
                        {
                            continue;
                        }
                    }

                    // Alarm verildiği anı sözlüğe kaydet
                    _lastAlarmTimes[sourceIp] = DateTime.UtcNow;

                    // Görselleştirme ve Konsol Çıktısı
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\n[ALERT - {rule.RuleName}] !!! KRİTİK GÜVENLİK OLAYI !!!");
                    Console.WriteLine($"-> Kaynak IP: {sourceIp}");
                    Console.WriteLine($"-> Tespit Edilen Deneme Sayısı: {alert.Count}");
                    Console.WriteLine($"-> Kural Detayı: {rule.Description}");
                    Console.ResetColor();
                }
            }
        }
    }
}