import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Main class to run the application
public class SecureFileEncryptionTool {
    public static void main(String[] args) {
        try {
            AuthenticationManager authManager = new AuthenticationManager();
            KeyManager keyManager = new KeyManager();
            FileEncryptionEngine encryptionEngine = new FileEncryptionEngine();
            SecurityLogger logger = new SecurityLogger();
            
            CLIApplication app = new CLIApplication(authManager, keyManager, encryptionEngine, logger);
            app.start();
        } catch (Exception e) {
            System.err.println("Fatal error starting application: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

// Main application controller
class CLIApplication {
    private AuthenticationManager authManager;
    private KeyManager keyManager;
    private FileEncryptionEngine encryptionEngine;
    private SecurityLogger logger;
    private Scanner scanner;
    private User currentUser;
    private boolean isRunning;
    
    public CLIApplication(AuthenticationManager authManager, KeyManager keyManager, 
                         FileEncryptionEngine encryptionEngine, SecurityLogger logger) {
        this.authManager = authManager;
        this.keyManager = keyManager;
        this.encryptionEngine = encryptionEngine;
        this.logger = logger;
        this.scanner = new Scanner(System.in);
        this.isRunning = true;
    }
    
    public void start() {
        displayWelcomeBanner();
        
        // User authentication
        if (!authenticateUser()) {
            System.out.println("Authentication failed. Exiting application.");
            return;
        }
        
        logger.log("User '" + currentUser.getUsername() + "' logged in successfully");
        
        // Main application loop
        while (isRunning) {
            try {
                displayMainMenu();
                int choice = getUserChoice();
                processMenuChoice(choice);
            } catch (Exception e) {
                System.out.println("Unexpected error: " + e.getMessage());
                logger.log("Error in main loop: " + e.getMessage());
            }
        }
        
        shutdown();
    }
    
    private void displayWelcomeBanner() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("      SECURE FILE ENCRYPTION TOOL");
        System.out.println("           Advanced AES-128 GCM");
        System.out.println("=".repeat(50));
        System.out.println("🔒 Military-Grade Encryption");
        System.out.println("🌐 Cross-Platform Compatibility");
        System.out.println("📁 Support for All File Types");
        System.out.println("=".repeat(50) + "\n");
    }
    
    private boolean authenticateUser() {
        System.out.println("=== USER AUTHENTICATION ===");
        
        int attempts = 0;
        while (attempts < 3) {
            System.out.print("Username: ");
            String username = scanner.nextLine().trim();
            System.out.print("Password: ");
            String password = scanner.nextLine();
            
            User user = authManager.authenticate(username, password);
            if (user != null) {
                currentUser = user;
                System.out.println("✅ Authentication successful! Welcome, " + user.getUsername() + "!");
                return true;
            } else {
                attempts++;
                System.out.println("❌ Invalid credentials. Attempts remaining: " + (3 - attempts));
                logger.log("Failed login attempt for username: " + username);
            }
        }
        
        System.out.println("🚫 Maximum login attempts exceeded.");
        return false;
    }
    
    private void displayMainMenu() {
        System.out.println("\n" + "=".repeat(40));
        System.out.println("           MAIN MENU");
        System.out.println("=".repeat(40));
        System.out.println("1. 🔑 Generate New Encryption Key");
        System.out.println("2. 📁 Create New Text File");
        System.out.println("3. 🔒 Encrypt File");
        System.out.println("4. 🔓 Decrypt File");
        System.out.println("5. 📊 View File Information");
        System.out.println("6. 👤 User Management");
        System.out.println("7. 📋 Security Log");
        System.out.println("8. ℹ️  System Information");
        System.out.println("9. 🚪 Logout & Exit");
        System.out.println("=".repeat(40));
        System.out.print("Enter your choice (1-9): ");
    }
    
    private int getUserChoice() {
        try {
            String input = scanner.nextLine().trim();
            return Integer.parseInt(input);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    private void processMenuChoice(int choice) {
        switch (choice) {
            case 1:
                generateEncryptionKey();
                break;
            case 2:
                createNewFile();
                break;
            case 3:
                encryptFile();
                break;
            case 4:
                decryptFile();
                break;
            case 5:
                viewFileInformation();
                break;
            case 6:
                manageUsers();
                break;
            case 7:
                viewSecurityLog();
                break;
            case 8:
                showSystemInfo();
                break;
            case 9:
                logoutAndExit();
                break;
            default:
                System.out.println("❌ Invalid option! Please choose 1-9.");
        }
    }
    
    private void generateEncryptionKey() {
        System.out.println("\n=== GENERATE ENCRYPTION KEY ===");
        
        try {
            System.out.print("Enter key name (or press Enter for default): ");
            String keyName = scanner.nextLine().trim();
            if (keyName.isEmpty()) {
                keyName = "default";
            }
            
            System.out.print("Enter key strength (128/192/256): ");
            int keyStrength = Integer.parseInt(scanner.nextLine().trim());
            
            keyManager.generateKey(keyName, keyStrength, currentUser);
            System.out.println("✅ Encryption key '" + keyName + "' generated successfully!");
            logger.log("User '" + currentUser.getUsername() + "' generated key: " + keyName);
            
        } catch (Exception e) {
            System.out.println("❌ Key generation failed: " + e.getMessage());
            logger.log("Key generation failed: " + e.getMessage());
        }
    }
    
    private void createNewFile() {
        System.out.println("\n=== CREATE NEW TEXT FILE ===");
        
        System.out.print("Enter file path: ");
        String filePath = scanner.nextLine().trim();
        
        if (filePath.isEmpty()) {
            System.out.println("❌ File path cannot be empty!");
            return;
        }
        
        System.out.println("Enter file content (type 'END' on a new line to finish):");
        StringBuilder content = new StringBuilder();
        String line;
        
        while (!(line = scanner.nextLine()).equals("END")) {
            content.append(line).append("\n");
        }
        
        try {
            FileCreator.createFile(filePath, content.toString());
            System.out.println("✅ File created successfully: " + filePath);
            logger.log("User '" + currentUser.getUsername() + "' created file: " + filePath);
        } catch (IOException e) {
            System.out.println("❌ Error creating file: " + e.getMessage());
        }
    }
    
    private void encryptFile() {
        System.out.println("\n=== ENCRYPT FILE ===");
        
        System.out.print("Enter source file path: ");
        String inputFile = scanner.nextLine().trim();
        
        System.out.print("Enter output file path: ");
        String outputFile = scanner.nextLine().trim();
        
        System.out.print("Enter key name to use (or press Enter for default): ");
        String keyName = scanner.nextLine().trim();
        if (keyName.isEmpty()) {
            keyName = "default";
        }
        
        try {
            long startTime = System.currentTimeMillis();
            encryptionEngine.encryptFile(inputFile, outputFile, keyName, currentUser);
            long endTime = System.currentTimeMillis();
            
            System.out.println("✅ File encrypted successfully: " + outputFile);
            System.out.println("⏱️  Encryption time: " + (endTime - startTime) + "ms");
            logger.log("User '" + currentUser.getUsername() + "' encrypted: " + inputFile + " -> " + outputFile);
            
        } catch (Exception e) {
            System.out.println("❌ Encryption failed: " + e.getMessage());
            logger.log("Encryption failed: " + e.getMessage());
        }
    }
    
    private void decryptFile() {
        System.out.println("\n=== DECRYPT FILE ===");
        
        System.out.print("Enter encrypted file path: ");
        String inputFile = scanner.nextLine().trim();
        
        System.out.print("Enter output file path: ");
        String outputFile = scanner.nextLine().trim();
        
        System.out.print("Enter key name to use (or press Enter for default): ");
        String keyName = scanner.nextLine().trim();
        if (keyName.isEmpty()) {
            keyName = "default";
        }
        
        try {
            long startTime = System.currentTimeMillis();
            encryptionEngine.decryptFile(inputFile, outputFile, keyName, currentUser);
            long endTime = System.currentTimeMillis();
            
            System.out.println("✅ File decrypted successfully: " + outputFile);
            System.out.println("⏱️  Decryption time: " + (endTime - startTime) + "ms");
            logger.log("User '" + currentUser.getUsername() + "' decrypted: " + inputFile + " -> " + outputFile);
            
        } catch (Exception e) {
            System.out.println("❌ Decryption failed: " + e.getMessage());
            logger.log("Decryption failed: " + e.getMessage());
        }
    }
    
    private void viewFileInformation() {
        System.out.println("\n=== FILE INFORMATION ===");
        
        System.out.print("Enter file path: ");
        String filePath = scanner.nextLine().trim();
        
        try {
            FileInfo fileInfo = new FileInfo(filePath);
            fileInfo.displayInfo();
            logger.log("User '" + currentUser.getUsername() + "' viewed info for: " + filePath);
        } catch (IOException e) {
            System.out.println("❌ Error reading file: " + e.getMessage());
        }
    }
    
    private void manageUsers() {
        System.out.println("\n=== USER MANAGEMENT ===");
        
        if (!currentUser.isAdmin()) {
            System.out.println("❌ Access denied! Administrator privileges required.");
            return;
        }
        
        System.out.println("1. List Users");
        System.out.println("2. Add User");
        System.out.println("3. Delete User");
        System.out.print("Choose option: ");
        
        try {
            int option = Integer.parseInt(scanner.nextLine().trim());
            switch (option) {
                case 1:
                    authManager.listUsers();
                    break;
                case 2:
                    System.out.print("Enter new username: ");
                    String newUser = scanner.nextLine().trim();
                    System.out.print("Enter password: ");
                    String newPass = scanner.nextLine();
                    System.out.print("Is admin? (yes/no): ");
                    boolean isAdmin = scanner.nextLine().trim().equalsIgnoreCase("yes");
                    authManager.addUser(newUser, newPass, isAdmin);
                    break;
                case 3:
                    System.out.print("Enter username to delete: ");
                    String delUser = scanner.nextLine().trim();
                    authManager.deleteUser(delUser);
                    break;
                default:
                    System.out.println("Invalid option!");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    private void viewSecurityLog() {
        System.out.println("\n=== SECURITY LOG ===");
        logger.displayLog(currentUser);
    }
    
    private void showSystemInfo() {
        System.out.println("\n=== SYSTEM INFORMATION ===");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("JVM Vendor: " + System.getProperty("java.vendor"));
        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        System.out.println("Available Keys: " + keyManager.getAvailableKeys().size());
        System.out.println("Logged in as: " + currentUser.getUsername() + (currentUser.isAdmin() ? " (Admin)" : ""));
        System.out.println("Security Log Entries: " + logger.getLogCount());
    }
    
    private void logoutAndExit() {
        System.out.println("\nLogging out user: " + currentUser.getUsername());
        logger.log("User '" + currentUser.getUsername() + "' logged out");
        isRunning = false;
    }
    
    private void shutdown() {
        System.out.println("\nThank you for using Secure File Encryption Tool!");
        System.out.println("🔒 Your data security is our priority!");
        scanner.close();
    }
}

// User management and authentication
class AuthenticationManager {
    private Map<String, User> users;
    private SecureRandom random;
    
    public AuthenticationManager() {
        this.users = new ConcurrentHashMap<>();
        this.random = new SecureRandom();
        initializeDefaultUsers();
    }
    
    private void initializeDefaultUsers() {
        // Add default admin user
        users.put("admin", new User("admin", hashPassword("admin123"), true));
        // Add default regular user
        users.put("user", new User("user", hashPassword("user123"), false));
    }
    
    public User authenticate(String username, String password) {
        User user = users.get(username);
        if (user != null && user.getPasswordHash().equals(hashPassword(password))) {
            return user;
        }
        return null;
    }
    
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
    
    public void addUser(String username, String password, boolean isAdmin) {
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("User already exists: " + username);
        }
        users.put(username, new User(username, hashPassword(password), isAdmin));
        System.out.println("✅ User '" + username + "' added successfully!");
    }
    
    public void deleteUser(String username) {
        if (username.equals("admin")) {
            throw new IllegalArgumentException("Cannot delete admin user!");
        }
        if (users.remove(username) != null) {
            System.out.println("✅ User '" + username + "' deleted successfully!");
        } else {
            System.out.println("❌ User not found: " + username);
        }
    }
    
    public void listUsers() {
        System.out.println("\n=== REGISTERED USERS ===");
        for (User user : users.values()) {
            System.out.println("- " + user.getUsername() + (user.isAdmin() ? " (Admin)" : " (User)"));
        }
    }
}

// User entity class
class User {
    private String username;
    private String passwordHash;
    private boolean isAdmin;
    
    public User(String username, String passwordHash, boolean isAdmin) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.isAdmin = isAdmin;
    }
    
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public boolean isAdmin() { return isAdmin; }
}

// Enhanced Key Manager with multiple key support
class KeyManager {
    private Map<String, SecretKey> keys;
    private static final String KEY_DIRECTORY = "keys/";
    
    public KeyManager() {
        this.keys = new ConcurrentHashMap<>();
        loadExistingKeys();
    }
    
    public void generateKey(String keyName, int keyStrength, User user) throws Exception {
        if (!user.isAdmin() && !keyName.equals("default")) {
            throw new SecurityException("Only administrators can create named keys!");
        }
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyStrength, new SecureRandom());
        SecretKey key = keyGen.generateKey();
        
        keys.put(keyName, key);
        saveKeyToFile(keyName, key);
    }
    
    public SecretKey getKey(String keyName, User user) throws Exception {
        SecretKey key = keys.get(keyName);
        if (key == null) {
            key = loadKeyFromFile(keyName);
            keys.put(keyName, key);
        }
        
        if (!user.isAdmin() && !keyName.equals("default")) {
            throw new SecurityException("Access denied to key: " + keyName);
        }
        
        return key;
    }
    
    private void saveKeyToFile(String keyName, SecretKey key) throws IOException {
        Path keyDir = Paths.get(KEY_DIRECTORY);
        if (!Files.exists(keyDir)) {
            Files.createDirectories(keyDir);
        }
        
        Path keyFile = keyDir.resolve(keyName + ".key");
        try (FileOutputStream fos = new FileOutputStream(keyFile.toFile())) {
            fos.write(key.getEncoded());
        }
    }
    
    private SecretKey loadKeyFromFile(String keyName) throws IOException {
        Path keyFile = Paths.get(KEY_DIRECTORY, keyName + ".key");
        if (!Files.exists(keyFile)) {
            throw new FileNotFoundException("Key not found: " + keyName);
        }
        
        byte[] keyBytes = Files.readAllBytes(keyFile);
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    private void loadExistingKeys() {
        File keyDir = new File(KEY_DIRECTORY);
        if (keyDir.exists() && keyDir.isDirectory()) {
            File[] keyFiles = keyDir.listFiles((dir, name) -> name.endsWith(".key"));
            if (keyFiles != null) {
                for (File keyFile : keyFiles) {
                    String keyName = keyFile.getName().replace(".key", "");
                    try {
                        SecretKey key = loadKeyFromFile(keyName);
                        keys.put(keyName, key);
                    } catch (IOException e) {
                        System.err.println("Warning: Could not load key: " + keyName);
                    }
                }
            }
        }
    }
    
    public Set<String> getAvailableKeys() {
        return keys.keySet();
    }
}

// Enhanced File Encryption Engine with AES-GCM
class FileEncryptionEngine {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static final int BUFFER_SIZE = 8192;
    
    public void encryptFile(String inputPath, String outputPath, String keyName, User user) throws Exception {
        KeyManager keyManager = new KeyManager(); // In real app, inject this
        SecretKey key = keyManager.getKey(keyName, user);
        
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputPath);
        }
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputPath)) {
            
            // Write IV to output file
            fos.write(iv);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encrypted = cipher.update(buffer, 0, bytesRead);
                if (encrypted != null) {
                    fos.write(encrypted);
                }
            }
            
            byte[] finalEncrypted = cipher.doFinal();
            if (finalEncrypted != null) {
                fos.write(finalEncrypted);
            }
        }
    }
    
    public void decryptFile(String inputPath, String outputPath, String keyName, User user) throws Exception {
        KeyManager keyManager = new KeyManager();
        SecretKey key = keyManager.getKey(keyName, user);
        
        try (FileInputStream fis = new FileInputStream(inputPath)) {
            // Read IV from input file
            byte[] iv = new byte[IV_LENGTH];
            if (fis.read(iv) != iv.length) {
                throw new IOException("Invalid encrypted file format");
            }
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] decrypted = cipher.update(buffer, 0, bytesRead);
                    if (decrypted != null) {
                        fos.write(decrypted);
                    }
                }
                
                byte[] finalDecrypted = cipher.doFinal();
                if (finalDecrypted != null) {
                    fos.write(finalDecrypted);
                }
            }
        } catch (BadPaddingException e) {
            throw new SecurityException("Decryption failed - possible tampering or wrong key", e);
        }
    }
}

// File creation utility
class FileCreator {
    public static void createFile(String filePath, String content) throws IOException {
        File file = new File(filePath);
        File parentDir = file.getParentFile();
        
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }
        
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}

// File information utility
class FileInfo {
    private File file;
    
    public FileInfo(String filePath) {
        this.file = new File(filePath);
    }
    
    public void displayInfo() throws IOException {
        if (!file.exists()) {
            throw new FileNotFoundException("File does not exist");
        }
        
        System.out.println("File Name: " + file.getName());
        System.out.println("Absolute Path: " + file.getAbsolutePath());
        System.out.println("Size: " + file.length() + " bytes");
        System.out.println("Last Modified: " + new Date(file.lastModified()));
        System.out.println("Readable: " + file.canRead());
        System.out.println("Writable: " + file.canWrite());
        System.out.println("Executable: " + file.canExecute());
        System.out.println("Is Directory: " + file.isDirectory());
    }
}

// Security logging system
class SecurityLogger {
    private static final String LOG_FILE = "security.log";
    private int logCount;
    
    public SecurityLogger() {
        logCount = 0;
    }
    
    public void log(String message) {
        String timestamp = new Date().toString();
        String logEntry = String.format("[%s] %s", timestamp, message);
        
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
            logCount++;
        } catch (IOException e) {
            System.err.println("Could not write to log file: " + e.getMessage());
        }
    }
    
    public void displayLog(User user) {
        if (!user.isAdmin()) {
            System.out.println("❌ Access denied! Administrator privileges required.");
            return;
        }
        
        File logFile = new File(LOG_FILE);
        if (!logFile.exists()) {
            System.out.println("No security log entries found.");
            return;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(LOG_FILE))) {
            String line;
            int count = 0;
            System.out.println("\n=== SECURITY LOG ENTRIES ===");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
                count++;
            }
            System.out.println("Total entries: " + count);
        } catch (IOException e) {
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }
    
    public int getLogCount() {
        return logCount;
    }
}