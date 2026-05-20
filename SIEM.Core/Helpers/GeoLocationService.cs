using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;

namespace SIEM.Core.Helpers
{
    public class GeoLocationService
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public async Task<(string Country, string City)> GetLocationAsync(string ip)
        {
            try
            {
                // ip-api.com üzerinden ücretsiz sorgu yapıyoruz
                var response = await _httpClient.GetFromJsonAsync<GeoResponse>($"http://ip-api.com/json/{ip}");
                return (response?.country ?? "Unknown", response?.city ?? "Unknown");
            }
            catch
            {
                return ("Unknown", "Unknown");
            }
        }
    }

    public class GeoResponse
    {
        public string country { get; set; }
        public string city { get; set; }
    }
}
