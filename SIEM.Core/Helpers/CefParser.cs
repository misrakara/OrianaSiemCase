using System.Text.RegularExpressions;
using SIEM.Core.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace SIEM.Core.Helpers
{
    public static class CefParser
    {
        // CEF Header Regex
        private static readonly Regex CefHeaderRegex = new Regex(
            @"^CEF:(?<version>\d+)\|(?<vendor>[^|]+)\|(?<product>[^|]+)\|(?<devVersion>[^|]+)\|(?<eventId>[^|]+)\|(?<name>[^|]+)\|(?<severity>[^|]+)\|",
            RegexOptions.Compiled);

        // Extension Regex
        private static readonly Regex ExtensionRegex = new Regex(
            @"(?<key>\w+)=(?<value>[^=]+?)(?=\s+\w+=|$)",
            RegexOptions.Compiled);

        /// <summary>
        /// MongoDB'nin reddettiği (Invalid UTF-8) veya hata verdiği karakterleri temizler.
        /// </summary>
        public static string SanitizeForMongo(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";

            // 1. Null byte (\x00) karakterini temizle (MongoDB'nin en büyük düşmanı)
            string cleanStr = input.Replace("\0", "");

            // 2. UTF-8 dışı bozuk karakterleri temizlemek için byte dizisine çevirip tekrar decode et
            // errors="ignore" mantığının C# karşılığıdır.
            byte[] utf8Bytes = Encoding.UTF8.GetBytes(cleanStr);
            return Encoding.UTF8.GetString(utf8Bytes).Trim();
        }

        public static LogModel Parse(string rawLog, string sourceIp, string protocol)
        {
            var model = new LogModel
            {
                RawData = SanitizeForMongo(rawLog), // Ham veriyi de temizleyerek başla
                SourceIp = SanitizeForMongo(sourceIp),
                Protocol = SanitizeForMongo(protocol),
                LogTime = DateTime.UtcNow
            };

            try
            {
                if (string.IsNullOrWhiteSpace(rawLog)) return model;

                // 1. Header Ayrıştırma
                var headerMatch = CefHeaderRegex.Match(rawLog);
                if (headerMatch.Success)
                {
                    model.CefVersion = SanitizeForMongo(headerMatch.Groups["version"].Value);
                    model.Vendor = SanitizeForMongo(headerMatch.Groups["vendor"].Value);
                    model.Product = SanitizeForMongo(headerMatch.Groups["product"].Value);
                    model.DeviceVersion = SanitizeForMongo(headerMatch.Groups["devVersion"].Value);
                    model.DeviceEventClassId = SanitizeForMongo(headerMatch.Groups["eventId"].Value);
                    model.Name = SanitizeForMongo(headerMatch.Groups["name"].Value);
                    model.Severity = SanitizeForMongo(headerMatch.Groups["severity"].Value);

                    // 2. Extension Ayrıştırma
                    string extensionPart = rawLog.Substring(headerMatch.Length);

                    if (!string.IsNullOrWhiteSpace(extensionPart))
                    {
                        var extensionMatches = ExtensionRegex.Matches(extensionPart);
                        foreach (Match match in extensionMatches)
                        {
                            string key = SanitizeForMongo(match.Groups["key"].Value);
                            string value = SanitizeForMongo(match.Groups["value"].Value); // Regex'te "val" değil "value" kullanmışsın, düzelttim

                            if (!string.IsNullOrEmpty(key))
                            {
                                model.Extensions[key] = value;
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Parse hatası olsa bile RawData sayesinde veri kaybı yaşanmaz
            }

            return model;
        }
    }
}