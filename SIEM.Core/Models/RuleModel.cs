using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIEM.Core.Models
{
    public class RuleModel
    {
        public string RuleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string FieldToTrack { get; set; } = string.Empty; // Takip edilecek alan (örn: Extensions.src)
        public int Threshold { get; set; } // Eşik değeri (örn: 5 deneme)
        public int TimeWindowMinutes { get; set; } // Zaman penceresi (örn: 1 dakika)
        public string AlertSeverity { get; set; } = "High";
    }
}
