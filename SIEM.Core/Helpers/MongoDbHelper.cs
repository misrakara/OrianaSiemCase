using MongoDB.Driver;
using SIEM.Core.Models;

namespace SIEM.Core.Helpers
{
    public class MongoDbHelper
    {
        private readonly IMongoCollection<LogModel> _logCollection;
        private readonly IMongoDatabase _database;

        public MongoDbHelper()
        {
            // 1. Veritabanı Bağlantısını Kur
            var client = new MongoClient("mongodb://localhost:27017");
            _database = client.GetDatabase("SiemDb");
            _logCollection = _database.GetCollection<LogModel>("Logs");

            // 2. İndeksleme İşlemi (Performans Optimizasyonu)
            try
            {
                // SourceIp (Artan) ve LogDate (Azalan) için bileşik indeks tanımı
                var indexKeysDefinition = Builders<LogModel>.IndexKeys
                    .Ascending(l => l.SourceIp)
                    .Descending(l => l.LogDate);

                // İndeks ismini belirleyerek oluştur (Senkron yöntemle)
                var indexOptions = new CreateIndexOptions { Name = "UX_SourceIp_LogDate" };
                _logCollection.Indexes.CreateOne(new CreateIndexModel<LogModel>(indexKeysDefinition, indexOptions));
            }
            catch (Exception ex)
            {
                // İndeks zaten varsa veya bir sorun oluşursa programın çökmesini engelleriz
                Console.WriteLine($"[VERİTABANI NOTU] İndeks oluşturma atlandı veya zaten mevcut: {ex.Message}");
            }
        }

        // Program.cs'in veritabanı referansına erişmesi için
        public IMongoDatabase GetDatabase()
        {
            return _database;
        }

        // Logları kaydetme metodu
        public async Task SaveLogAsync(LogModel log)
        {
            await _logCollection.InsertOneAsync(log);
        }
    }
}