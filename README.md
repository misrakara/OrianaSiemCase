# OrianaSiemCase
# 🛡️ Oriana SIEM - UDP/TCP Log Toplama ve Korelasyon Uygulaması

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Environment](https://img.shields.io/badge/staj--d%C3%B6nemi-%C4%B0%C5%9Fyeri%20E%C4%9Fitimi%202026-orange.svg)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)
![Build](https://img.shields.io/badge/build-passing-success.svg)
![Security](https://img.shields.io/badge/mTLS-Secured-brightgreen.svg)

**Heterojen ağlardan gelen siber güvenlik verilerini toplayan, anlamlandıran ve proaktif olarak raporlayan modern NoSQL tabanlı SIEM çözümü**

[Genel Bakış](#-genel-bakış) • [Proje Gelişim Aşamaları](#-proje-gelişim-aşamaları-ve-mimari) • [Teknik Spektrum](#-teknik-spektrum) • [Hızlı Başlangıç](#-kurulum-ve-sistem-gereksinimleri) • [Kod Mimarisi](#-proje-kaynak-kod-mimarisi) • [Gelişmiş Özellikler](#-geli%C5%9Fmi%C5%9F-%C3%B6zellikler-ve-mant%C4%B1ksal-kurallar)

</div>

---

## 🎯 Genel Bakış

[cite_start]Bu çalışma, **Oriana Tech** bünyesinde gerçekleştirilen İşyeri Eğitimi kapsamında geliştirilmiştir[cite: 2]. [cite_start]Çözüm; ağ üzerindeki dağınık log verilerini merkezi bir mimaride toplayarak normalize etmek, güvenlik şiddetine göre korele etmek ve SOC (Güvenlik Operasyon Merkezi) ekiplerinin anlık müdahale edebileceği interaktif bir dashboard sunmak amacıyla tasarlanmıştır[cite: 3, 56].

---

## 🚀 Proje Gelişim Aşamaları ve Mimari

[cite_start]Sistem, ham log verisinin siber güvenlik istihbaratına dönüşme sürecini 5 ana aşamada asenkron olarak yürütür[cite: 5, 131]:

1. [cite_start]**Ingestion (Veri Toplama):** Ağ trafiğini simüle eden C# .NET tabanlı `TestSender` yazılımı ile besleme yapılır[cite: 6]. Testler üç senaryoda doğrulanmıştır:
   * [cite_start]**Manuel Tekil Gönderim (UDP):** Standart log iletim doğrulaması[cite: 8].
   * [cite_start]**Güvenli Tekil Gönderim (TCP-mTLS):** Çift taraflı sertifika doğrulama (mTLS) mekanizması[cite: 8].
   * [cite_start]**Hibrit Toplu Simülasyon:** Yük altında veri kaybını test etmek amacıyla 100+ paket karma dağıtılarak dinlenir[cite: 9].
2. [cite_start]**Parsing & Normalization:** Karmaşık metin yığınları Regex ve key-value eşleşmeleriyle yapılandırılmış nesnelere dönüştürülür[cite: 10].
3. [cite_start]**Persistence (Veri Saklama):** Yapılandırılmış veriler ve ham loglar NoSQL mimaride (**MongoDB**) arşivlenir[cite: 11].
4. [cite_start]**Correlation & Analysis:** CEF formatındaki `Severity` alanı 0-10 skalasında değerlendirilir[cite: 12]:
   * [cite_start]🔵 **Düşük (0-3):** Genel sistem bilgilendirmeleri ve başarılı kullanıcı girişleri[cite: 13, 14].
   * [cite_start]🟠 **Orta (4-7):** Şüpheli aktiviteler, ardışık başarısız giriş denemeleri (İnceleme Gerektirir)[cite: 15].
   * 🔴 **Yüksek/Kritik (8-10):** Doğrudan tehditler (Malware, Unauthorized Access). [cite_start]Dashboard'da kırmızı renkle önceliklendirilir[cite: 16, 17].
5. [cite_start]**Visualization & Reporting:** Verileri anlamlı siber istihbarata dönüştüren **Streamlit** tabanlı görselleştirme katmanıdır[cite: 18, 19].

---

## 📚 Teknik Spektrum

### Teknoloji Stack

| Katman | Teknoloji | Fonksiyon |
| :--- | :--- | :--- |
| **Backend** | Python 3.10 | [cite_start]Core logic, veri fallback mekanizmaları, otonom raporlama motoru. |
| **mTLS Güvenliği** | SSL/TLS | [cite_start]TCP iletişiminde çift taraflı dijital sertifika doğrulaması. |
| **Veritabanı** | MongoDB | [cite_start]Ham ve parse edilmiş logların NoSQL mimaride saklanması. |
| **Dashboard** | Streamlit | [cite_start]Gerçek zamanlı izleme, dinamik filtreleme ve SOC arayüzü. |
| **Simülasyon / Collector** | C# .NET | [cite_start]Saldırı senaryosu üreten `TestSender` ve asenkron socket collector (`SIEM.Scanner`). |
| **Görselleştirme** | Plotly & Pandas | [cite_start]Zaman serisi analizleri ve küresel tehdit haritası (Bubble Chart)[cite: 21, 286]. |

---

## 🛠️ Kurulum ve Sistem Gereksinimleri

### Ön Gereksinimler
* [cite_start]**MongoDB:** `localhost:27017` portu üzerinde yerel bir servis aktif olmalıdır[cite: 26].
* [cite_start]**Python (v3.10+):** Dashboard ve PDF modülü için gereklidir[cite: 27].
* [cite_start]**.NET SDK (v8.0):** C# projelerinin (`Scanner` ve `TestSender`) derlenmesi için kurulmalıdır[cite: 28].

### 1️⃣ Bağımlılıkların Yüklenmesi (Python)
[cite_start]Terminali projenin kök dizininde açarak gerekli kütüphaneleri yükleyin[cite: 30]:
```bash
pip install streamlit pymongo pandas plotly fpdf
