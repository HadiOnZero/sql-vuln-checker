import SwiftUI

struct ContentView: View {
    @State private var inputText = ""
    @State private var analysisResults: [SQLPattern] = []
    @State private var isAnalyzing = false
    @State private var currentRiskLevel: RiskLevel = .safe
    @State private var showingAlert = false
    @State private var alertMessage = ""
    @State private var showingShareSheet = false
    
    private let sqlPatterns = [
        SQLPattern(name: "Union-based SQL Injection",
                  pattern: "(union\\s+select|union\\s+all\\s+select)",
                  risk: .high,
                  description: "Menggunakan UNION untuk menggabungkan hasil query"),
        SQLPattern(name: "Boolean-based SQL Injection",
                  pattern: "(and\\s+1=1|or\\s+1=1|and\\s+1=2|or\\s+1=2)",
                  risk: .high,
                  description: "Manipulasi kondisi boolean untuk ekstraksi data"),
        SQLPattern(name: "Time-based SQL Injection",
                  pattern: "(sleep\\s*\\(|waitfor\\s+delay|benchmark\\s*\\()",
                  risk: .medium,
                  description: "Menggunakan fungsi delay untuk blind injection"),
        SQLPattern(name: "Comment-based Injection",
                  pattern: "(--\\s|/\\*|\\*/|#)",
                  risk: .medium,
                  description: "Menggunakan komentar SQL untuk bypass filter"),
        SQLPattern(name: "Quote Manipulation",
                  pattern: "('|\"|`)",
                  risk: .low,
                  description: "Manipulasi tanda kutip yang mencurigakan"),
        SQLPattern(name: "SQL Keywords",
                  pattern: "(drop\\s+table|delete\\s+from|insert\\s+into|update\\s+set|alter\\s+table)",
                  risk: .high,
                  description: "Kata kunci SQL yang berpotensi berbahaya"),
        SQLPattern(name: "Information Schema Access",
                  pattern: "(information_schema|sysobjects|syscolumns)",
                  risk: .high,
                  description: "Akses ke schema database untuk reconnaissance"),
        SQLPattern(name: "Hex Encoding",
                  pattern: "(0x[0-9a-f]+)",
                  risk: .medium,
                  description: "Encoding hexadecimal untuk bypass filter")
    ]
    
    private let samplePayloads = [
        "' OR '1'='1",
        "admin'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "1' AND SLEEP(5) --",
        "' OR 1=1 LIMIT 1 OFFSET 0 --"
    ]
    
    var body: some View {
        NavigationView {
            ZStack {
                // Gradient background
                LinearGradient(
                    colors: [
                        Color(red: 0.10, green: 0.10, blue: 0.18),
                        Color(red: 0.09, green: 0.13, blue: 0.24),
                        Color(red: 0.06, green: 0.20, blue: 0.38)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()
                
                ScrollView {
                    LazyVStack(spacing: 20) {
                        // Header
                        headerView
                        
                        // Input section
                        inputSectionView
                        
                        // Sample payloads
                        samplePayloadsView
                        
                        // Results section
                        if !analysisResults.isEmpty || (!inputText.isEmpty && !isAnalyzing) {
                            resultsSectionView
                        }
                        
                        // Info panels
                        infoPanelsView
                        
                        // Footer
                        footerView
                    }
                    .padding()
                }
            }
            .navigationBarHidden(true)
        }
        .alert("Pesan", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
        .sheet(isPresented: $showingShareSheet) {
            ShareSheet(items: [generateReportURL()])
        }
    }
    
    // MARK: - Header View
    var headerView: some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 36, weight: .bold))
                    .foregroundColor(.blue)
                
                Text("SQL Injection\nChecker")
                    .font(.system(size: 28, weight: .bold))
                    .foregroundColor(.white)
                    .multilineTextAlignment(.center)
            }
            
            Text("Deteksi kerentanan SQL injection dalam input Anda")
                .font(.system(size: 16, weight: .medium))
                .foregroundColor(.white.opacity(0.8))
                .multilineTextAlignment(.center)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.1))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.white.opacity(0.2), lineWidth: 1)
                )
        )
    }
    
    // MARK: - Input Section
    var inputSectionView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Input untuk Dianalisis")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(.primary)
            
            TextEditor(text: $inputText)
                .font(.system(.body, design: .monospaced))
                .padding()
                .background(Color(UIColor.systemBackground))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.blue.opacity(0.3), lineWidth: 1)
                )
                .frame(minHeight: 120)
            
            // Buttons
            HStack(spacing: 12) {
                Button(action: analyzeInput) {
                    HStack {
                        if isAnalyzing {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "magnifyingglass")
                        }
                        Text(isAnalyzing ? "Menganalisis..." : "Periksa Kerentanan")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(8)
                }
                .disabled(inputText.isEmpty || isAnalyzing)
                
                Button(action: copyToClipboard) {
                    Image(systemName: "doc.on.doc")
                        .frame(width: 44, height: 44)
                        .background(Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                }
                .disabled(inputText.isEmpty)
                
                if !analysisResults.isEmpty {
                    Button(action: shareReport) {
                        Image(systemName: "square.and.arrow.up")
                            .frame(width: 44, height: 44)
                            .background(Color.green)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(UIColor.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 4)
        )
    }
    
    // MARK: - Sample Payloads
    var samplePayloadsView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Contoh Payload untuk Testing:")
                .font(.subheadline)
                .fontWeight(.medium)
                .foregroundColor(.secondary)
            
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 200))], spacing: 8) {
                ForEach(samplePayloads, id: \.self) { payload in
                    Button(action: { inputText = payload }) {
                        Text(payload)
                            .font(.system(.caption, design: .monospaced))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .foregroundColor(.blue)
                            .cornerRadius(8)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.blue.opacity(0.3), lineWidth: 1)
                            )
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.systemBackground))
                .shadow(color: .black.opacity(0.05), radius: 4, x: 0, y: 2)
        )
    }
    
    // MARK: - Results Section
    var resultsSectionView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Hasil Analisis")
                    .font(.title2)
                    .fontWeight(.bold)
                
                Spacer()
                
                Text(currentRiskLevel.displayName)
                    .font(.caption)
                    .fontWeight(.bold)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(currentRiskLevel.color)
                    .foregroundColor(.white)
                    .cornerRadius(16)
            }
            
            if analysisResults.isEmpty {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.title2)
                    
                    Text("Tidak ditemukan pola SQL injection yang mencurigakan")
                        .foregroundColor(.green)
                        .fontWeight(.medium)
                }
                .padding()
                .background(Color.green.opacity(0.1))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.green.opacity(0.3), lineWidth: 1)
                )
            } else {
                LazyVStack(spacing: 12) {
                    ForEach(analysisResults.indices, id: \.self) { index in
                        ResultItemView(result: analysisResults[index])
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(UIColor.systemBackground))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(currentRiskLevel.color.opacity(0.3), lineWidth: 2)
                )
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 4)
        )
        .animation(.easeInOut, value: analysisResults)
    }
    
    // MARK: - Info Panels
    var infoPanelsView: some View {
        VStack(spacing: 16) {
            HStack(alignment: .top, spacing: 16) {
                // Risk levels
                VStack(alignment: .leading, spacing: 12) {
                    Text("Level Risiko")
                        .font(.headline)
                        .fontWeight(.bold)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(RiskLevel.allCases.reversed(), id: \.self) { risk in
                            HStack {
                                Circle()
                                    .fill(risk.color)
                                    .frame(width: 12, height: 12)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(risk.displayName.components(separatedBy: " ").last ?? "")
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    
                                    Text(risk.description)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                
                                Spacer()
                            }
                        }
                    }
                }
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color(UIColor.systemBackground))
                        .shadow(color: .black.opacity(0.05), radius: 4, x: 0, y: 2)
                )
                
                // Prevention tips
                VStack(alignment: .leading, spacing: 12) {
                    Text("Tips Pencegahan")
                        .font(.headline)
                        .fontWeight(.bold)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(preventionTips, id: \.self) { tip in
                            HStack(alignment: .top) {
                                Image(systemName: "checkmark")
                                    .foregroundColor(.green)
                                    .font(.caption)
                                    .padding(.top, 2)
                                
                                Text(tip)
                                    .font(.subheadline)
                                    .foregroundColor(.primary)
                                
                                Spacer()
                            }
                        }
                    }
                }
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color(UIColor.systemBackground))
                        .shadow(color: .black.opacity(0.05), radius: 4, x: 0, y: 2)
                )
            }
            
            // Statistics (if results available)
            if !analysisResults.isEmpty {
                statisticsView
            }
        }
    }
    
    var statisticsView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Statistik")
                .font(.headline)
                .fontWeight(.bold)
            
            VStack(spacing: 8) {
                StatRow(label: "Total Pola Terdeteksi", value: "\(analysisResults.count)")
                StatRow(label: "Risiko Tertinggi", value: currentRiskLevel.displayName)
                StatRow(label: "Panjang Input", value: "\(inputText.count) karakter")
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.systemBackground))
                .shadow(color: .black.opacity(0.05), radius: 4, x: 0, y: 2)
        )
    }
    
    // MARK: - Footer
    var footerView: some View {
        VStack(spacing: 8) {
            Text("⚠️ Tool ini hanya untuk tujuan edukasi dan testing keamanan yang sah.")
                .font(.caption)
                .foregroundColor(.white.opacity(0.7))
                .multilineTextAlignment(.center)
            
            Text("Jangan gunakan untuk aktivitas yang melanggar hukum.")
                .font(.caption)
                .foregroundColor(.white.opacity(0.7))
                .multilineTextAlignment(.center)
        }
        .padding()
    }
    
    // MARK: - Helper Properties
    var preventionTips: [String] {
        [
            "Gunakan prepared statements",
            "Validasi dan sanitasi input",
            "Terapkan prinsip least privilege",
            "Escape karakter khusus",
            "Gunakan ORM dengan benar"
        ]
    }
    
    // MARK: - Methods
    func analyzeInput() {
        guard !inputText.isEmpty else { return }
        
        isAnalyzing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            let results = self.analyzeSQLInput(self.inputText)
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                self.analysisResults = results
                self.updateRiskLevel(from: results)
                self.isAnalyzing = false
            }
        }
    }
    
    func analyzeSQLInput(_ input: String) -> [SQLPattern] {
        var detectedPatterns: [SQLPattern] = []
        
        for pattern in sqlPatterns {
            do {
                let regex = try NSRegularExpression(pattern: pattern.pattern, options: [.caseInsensitive])
                let matches = regex.matches(in: input, options: [], range: NSRange(location: 0, length: input.count))
                
                if !matches.isEmpty {
                    let examples = matches.prefix(3).compactMap { match in
                        Range(match.range, in: input).map { String(input[$0]) }
                    }
                    
                    var detectedPattern = pattern
                    detectedPattern.matches = matches.count
                    detectedPattern.examples = examples
                    detectedPatterns.append(detectedPattern)
                }
            } catch {
                print("Regex error for pattern: \(pattern.name)")
            }
        }
        
        return detectedPatterns
    }
    
    func updateRiskLevel(from results: [SQLPattern]) {
        let maxRisk = results.map { $0.risk }.max() ?? .safe
        currentRiskLevel = maxRisk
    }
    
    func copyToClipboard() {
        UIPasteboard.general.string = inputText
        alertMessage = "Teks berhasil disalin ke clipboard"
        showingAlert = true
    }
    
    func shareReport() {
        showingShareSheet = true
    }
    
    func generateReportURL() -> URL {
        let reportData: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "input": inputText,
            "riskLevel": currentRiskLevel.rawValue,
            "vulnerabilities": analysisResults.map { result in
                [
                    "name": result.name,
                    "risk": result.risk.rawValue,
                    "description": result.description,
                    "matches": result.matches,
                    "examples": result.examples
                ]
            }
        ]
        
        let jsonData = try! JSONSerialization.data(withJSONObject: reportData, options: .prettyPrinted)
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("sql-injection-report-\(Int(Date().timeIntervalSince1970)).json")
        
        try! jsonData.write(to: tempURL)
        return tempURL
    }
}

// MARK: - Supporting Views
struct ResultItemView: View {
    let result: SQLPattern
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(result.name)
                    .font(.subheadline)
                    .fontWeight(.bold)
                
                Spacer()
                
                Text(result.risk.displayName)
                    .font(.caption2)
                    .fontWeight(.bold)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(result.risk.color)
                    .foregroundColor(.white)
                    .cornerRadius(8)
            }
            
            Text(result.description)
                .font(.caption)
                .foregroundColor(.secondary)
            
            Text("Ditemukan: \(result.matches) kali")
                .font(.caption)
                .fontWeight(.medium)
            
            if !result.examples.isEmpty {
                Text("Contoh yang ditemukan:")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 100))], spacing: 4) {
                    ForEach(result.examples, id: \.self) { example in
                        Text(example)
                            .font(.system(.caption2, design: .monospaced))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color(UIColor.tertiarySystemBackground))
                            .cornerRadius(4)
                    }
                }
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemBackground))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(result.risk.color.opacity(0.3), lineWidth: 1)
        )
    }
}

struct StatRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label + ":")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            Spacer()
            
            Text(value)
                .font(.subheadline)
                .fontWeight(.bold)
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - Data Models
struct SQLPattern: Equatable {
    let name: String
    let pattern: String
    let risk: RiskLevel
    let description: String
    var matches: Int = 0
    var examples: [String] = []
    
    // Implement Equatable
    static func == (lhs: SQLPattern, rhs: SQLPattern) -> Bool {
        return lhs.name == rhs.name &&
               lhs.pattern == rhs.pattern &&
               lhs.risk == rhs.risk &&
               lhs.description == rhs.description &&
               lhs.matches == rhs.matches &&
               lhs.examples == rhs.examples
    }
}

enum RiskLevel: Int, CaseIterable, Comparable {
    case safe = 0
    case low = 1
    case medium = 2
    case high = 3
    
    static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
    
    var displayName: String {
        switch self {
        case .safe: return "AMAN"
        case .low: return "RISIKO RENDAH"
        case .medium: return "RISIKO SEDANG"
        case .high: return "RISIKO TINGGI"
        }
    }
    
    var color: Color {
        switch self {
        case .safe: return .green
        case .low: return .blue
        case .medium: return .orange
        case .high: return .red
        }
    }
    
    var description: String {
        switch self {
        case .safe: return "Tidak ditemukan ancaman"
        case .low: return "Indikasi pola mencurigakan"
        case .medium: return "Berpotensi mengekspos informasi"
        case .high: return "Berpotensi memberikan akses penuh"
        }
    }
}

#Preview {
    ContentView()
}
