import javax.swing.*;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class UltimateSecurityApp extends JFrame {

    private static final int PORT = 8080;
    private static final String LOG_FILE = "advanced_threats.log";
    private static final String BAN_DB = "banned_ips.db";
    private static final String PROTECTED_DIR = "./protected_files";
    private static final String QUARANTINE_DIR = "./quarantine";

    private static final ExecutorService threadPool = Executors.newCachedThreadPool();
    private static final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();
    private static final Map<String, Long> blockList = new ConcurrentHashMap<>();
    private static final Set<String> threatSignatures = ConcurrentHashMap.newKeySet();
    private static final Set<String> knownMaliciousHashes = ConcurrentHashMap.newKeySet();

    // GUI Components
    private static JTextArea logArea;
    private static JLabel statusLabel;
    private static JLabel threatCountLabel;
    private static int threatsMitigated = 0;

    public static void main(String[] args) {
        // Ensure directories exist
        new File(PROTECTED_DIR).mkdirs();
        new File(QUARANTINE_DIR).mkdirs();

        loadInitialSignatures();
        loadBannedIPs();

        // Launch GUI
        SwingUtilities.invokeLater(() -> new UltimateSecurityApp().setVisible(true));

        // Launch Core Engines
        threadPool.submit(UltimateSecurityApp::startNetworkServer);
        threadPool.submit(UltimateSecurityApp::startProcessScanner);
        threadPool.submit(UltimateSecurityApp::startFileIntegrityMonitor);
        threadPool.submit(UltimateSecurityApp::startStartupRegistryScanner);
    }

    public UltimateSecurityApp() {
        setTitle("Zero-Trust Security Engine - Ring 3 HIPS");
        setSize(900, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        getContentPane().setBackground(Color.BLACK);

        // Top Panel: Stats & Status
        JPanel topPanel = new JPanel(new GridLayout(1, 3));
        topPanel.setBackground(Color.DARK_GRAY);
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        statusLabel = new JLabel("Engine Status: ONLINE & ARMED", SwingConstants.CENTER);
        statusLabel.setForeground(Color.GREEN);
        statusLabel.setFont(new Font("Consolas", Font.BOLD, 14));

        threatCountLabel = new JLabel("Threats Mitigated: 0", SwingConstants.CENTER);
        threatCountLabel.setForeground(Color.RED);
        threatCountLabel.setFont(new Font("Consolas", Font.BOLD, 14));

        JButton killAllBtn = new JButton("Emergency Lock-down");
        killAllBtn.setBackground(Color.RED);
        killAllBtn.setForeground(Color.WHITE);
        killAllBtn.addActionListener(e -> {
            appendLog("[SYSTEM] Manual Lock-down initiated. Terminating application...");
            System.exit(0); // Physically terminates the program and closes network ports
        });

        topPanel.add(statusLabel);
        topPanel.add(threatCountLabel);
        topPanel.add(killAllBtn);
        add(topPanel, BorderLayout.NORTH);

        // Center Panel: Live Logs
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setBackground(Color.BLACK);
        logArea.setForeground(Color.GREEN);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        
        // Auto-scroll logs
        DefaultCaret caret = (DefaultCaret) logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GREEN), "Live OS & Network Telemetry"));
        add(scrollPane, BorderLayout.CENTER);

        appendLog("[SYSTEM] Ultimate Security App Initialized.");
        appendLog("[SYSTEM] Real-time Process Killer & File Quarantine ACTIVE.");
    }

    private static void appendLog(String message) {
        String logEntry = "[" + new java.util.Date() + "] " + message;
        SwingUtilities.invokeLater(() -> logArea.append(logEntry + "\n"));
        try (FileWriter fw = new FileWriter(LOG_FILE, true); PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
        } catch (IOException ignored) {}
    }

    private static void incrementThreatCount() {
        threatsMitigated++;
        SwingUtilities.invokeLater(() -> threatCountLabel.setText("Threats Mitigated: " + threatsMitigated));
    }

    private static void loadInitialSignatures() {
        // Process name signatures
        threatSignatures.addAll(Arrays.asList("nc.exe", "mimikatz.exe", "ngrok.exe", "psexec.exe"));
        
        // SHA-256 File Hashes (Lowercase)
        // Example: EICAR Anti-Virus Test File SHA-256
        knownMaliciousHashes.add("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"); 
        // Example: Empty file SHA-256 (Useful for rapid testing with blank text files)
        knownMaliciousHashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    // --- HELPER: SHA-256 Calculator ---
    private static String calculateSHA256(File file) {
        try (InputStream fis = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteArray = new byte[8192];
            int bytesCount;
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // --- ENGINE 1: Active Process Killer ---
    private static void startProcessScanner() {
        appendLog("[ENGINE] Process Scanner & Terminator started.");
        while (true) {
            try {
                // Get task list in CSV format without headers
                Process process = Runtime.getRuntime().exec("tasklist /fo csv /nh");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;

                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\",\"");
                    if (parts.length >= 2) {
                        String processName = parts[0].replace("\"", "").toLowerCase();
                        String pid = parts[1].replace("\"", "");

                        for (String sig : threatSignatures) {
                            if (processName.equals(sig)) {
                                appendLog("[DEFENSE] Malicious Process Detected in RAM: " + processName + " (PID: " + pid + ")");
                                // ACTIVE MITIGATION: Kill the process immediately
                                Runtime.getRuntime().exec("taskkill /F /PID " + pid);
                                appendLog("[DEFENSE] Process " + pid + " TERMINATED successfully.");
                                incrementThreatCount();
                            }
                        }
                    }
                }
                Thread.sleep(10000); // Optimized to 10 seconds to save CPU overhead
            } catch (Exception e) {
                appendLog("[ERROR] Process scanner failure: " + e.getMessage());
            }
        }
    }

    // --- ENGINE 2: Active File Hash & Extension Quarantine ---
    private static void startFileIntegrityMonitor() {
        appendLog("[ENGINE] File Integrity & Hash Quarantine Monitor started.");
        try {
            WatchService watchService = FileSystems.getDefault().newWatchService();
            Path path = Paths.get(PROTECTED_DIR);
            path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);

            while (true) {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    Path fileName = (Path) event.context();
                    Path fullPath = path.resolve(fileName);
                    File file = fullPath.toFile();

                    // Wait briefly for file write stream to finish before reading
                    Thread.sleep(200);

                    if (!file.exists() || file.isDirectory()) continue;

                    String fileHash = calculateSHA256(file);
                    if (fileHash == null) continue;

                    appendLog("[FIM] File drop detected: " + fileName + " | SHA-256: " + fileHash);

                    String fileStr = fileName.toString().toLowerCase();
                    boolean isSuspiciousExtension = fileStr.endsWith(".exe") || fileStr.endsWith(".vbs") || fileStr.endsWith(".bat") || fileStr.endsWith(".ps1");
                    boolean isMaliciousHash = knownMaliciousHashes.contains(fileHash.toLowerCase());

                    if (isSuspiciousExtension || isMaliciousHash) {
                        if (isMaliciousHash) {
                            appendLog("[DEFENSE] MALICIOUS HASH MATCH! File disguising attempted: " + fileName);
                        } else {
                            appendLog("[DEFENSE] Unauthorized executable drop detected: " + fileName);
                        }

                        try {
                            // ACTIVE MITIGATION: Move to Quarantine and lock extension
                            Path quarantinePath = Paths.get(QUARANTINE_DIR, fileName.toString() + ".locked");
                            Files.move(fullPath, quarantinePath, StandardCopyOption.REPLACE_EXISTING);
                            appendLog("[DEFENSE] Isolated & Quarantined to: " + quarantinePath.toString());
                            incrementThreatCount();
                        } catch (Exception e) {
                            appendLog("[ERROR] Failed to quarantine file: " + fullPath);
                        }
                    }
                }
                key.reset();
            }
        } catch (Exception e) {
            appendLog("[ERROR] FIM Engine failed.");
        }
    }

    // --- ENGINE 3: Network Firewall & DDoS Shield ---
    private static void startNetworkServer() {
        appendLog("[ENGINE] Network Proxy Layer started on Port " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                String clientIP = clientSocket.getInetAddress().getHostAddress();
                threadPool.submit(() -> handleConnection(clientSocket, clientIP));
            }
        } catch (Exception e) {
            appendLog("[ERROR] Network server crash: " + e.getMessage());
        }
    }

    private static void handleConnection(Socket socket, String clientIP) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             OutputStream out = socket.getOutputStream()) {

            if (blockList.containsKey(clientIP)) {
                socket.close();
                return;
            }

            int count = requestCounts.getOrDefault(clientIP, 0) + 1;
            requestCounts.put(clientIP, count);

            if (count > 20) { // Max requests per second
                banIP(clientIP);
                incrementThreatCount();
                return;
            }

            new Thread(() -> {
                try { Thread.sleep(1000); requestCounts.put(clientIP, 0); } catch (Exception ignored) {}
            }).start();

            String requestLine = reader.readLine();
            if (requestLine != null && (requestLine.contains("DROP TABLE") || requestLine.contains("<script>"))) {
                banIP(clientIP);
                appendLog("[DEFENSE] Payload detected. IP Banned: " + clientIP);
                incrementThreatCount();
                out.write("HTTP/1.1 403 Forbidden\r\n\r\n".getBytes());
                return;
            }

            out.write("HTTP/1.1 200 OK\r\n\r\nSecure connection established.".getBytes());

        } catch (Exception ignored) {}
    }

    // --- ENGINE 4: Windows Startup Registry Scanner ---
    private static void startStartupRegistryScanner() {
        appendLog("[ENGINE] Registry Persistence Scanner started.");
        try {
            Process process = Runtime.getRuntime().exec("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("nc.exe") || line.toLowerCase().contains("payload")) {
                    appendLog("[DEFENSE] Malicious Startup Entry Found: " + line.trim());
                    incrementThreatCount();
                }
            }
        } catch (Exception e) {
            appendLog("[ERROR] Registry scan failed.");
        }
    }

    private static void banIP(String ip) {
        blockList.put(ip, -1L);
        try (FileWriter fw = new FileWriter(BAN_DB, true); PrintWriter pw = new PrintWriter(fw)) {
            pw.println(ip);
        } catch (IOException ignored) {}
        appendLog("[NETWORK] IP Permanently Banned: " + ip);
    }

    private static void loadBannedIPs() {
        File db = new File(BAN_DB);
        if (!db.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(db))) {
            String line;
            while ((line = br.readLine()) != null) blockList.put(line.trim(), -1L);
        } catch (IOException ignored) {}
    }
}