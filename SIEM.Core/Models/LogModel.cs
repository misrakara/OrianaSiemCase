using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace SIEM.Core.Models
{
    public class LogModel
    {
        public string Country { get; set; } = "Unknown";
        public string City { get; set; } = "Unknown";

        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)] // MongoDB'ye utc formnatında kayıt sağlar 
        public DateTime LogTime { get; set; } = DateTime.UtcNow; // Global standart için Utc kullanımı önerilir. farklı zaman dilimleri için

        public string Protocol { get; set; } = "UDP";
        public string SourceIp { get; set; } = string.Empty;
        public string RawData { get; set; } = string.Empty;

        // --- CEF ---
        // Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension

        public string CefVersion { get; set; } = string.Empty; // Örn: 0 *** cef parser için eklendi.
        public string Vendor { get; set; } = string.Empty;    // Örn: OrianaTech
        public string Product { get; set; } = string.Empty;   // Örn: Firewall
        public string DeviceVersion { get; set; } = string.Empty; // Örn: 1.0[cite: 3] *** cef parser için eklendi.
        public string DeviceEventClassId { get; set; } = string.Empty; // Örn: 100[cite: 3] *** cef parser için eklendi.
        public string Name { get; set; } = string.Empty;      // Örn: Login Success[cite: 3]
        public string Severity { get; set; } = string.Empty;  // Örn: 3[cite: 3]
        // CEF log formatının tam spektrumunu karşılandı.


        // --- Dinamik Uzantılar (src, dst, dpt, suser vb.) ---
        // CEF logunun sonundaki tüm key-value çiftlerini burada saklayacağız[cite: 3]
        public Dictionary<string, string> Extensions { get; set; } = new Dictionary<string, string>();
        public object LogDate { get; internal set; }
    }
}