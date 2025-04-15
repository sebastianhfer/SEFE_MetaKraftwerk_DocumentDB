package de.metakraftwerk;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;

import org.bson.Document;
import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class MetaKraftwerkMongoDB {
    private static final Logger logger = Logger.getLogger(MetaKraftwerkMongoDB.class);
    static { BasicConfigurator.configure(); }

    private final String username;
    private final String password;
    private final String host;
    private final int port;
    private final String database;
    private final String urlQuery;
    private final String table;
    private MongoClient mongoClient;
    private MongoDatabase mongoDatabase;

    private static final String ALGORITHM = "AES";
    private static final int KEY_LENGTH = 256;
    private static final String SECRET_KEY = "4uUJ7tKS3%X:hS";

    public MetaKraftwerkMongoDB(String username, String password, String host, int port, String portStr, 
                               String database, String urlQuery, String table) {
        validateNotEmpty(username, "Username must not be empty");
        validateNotEmpty(password, "Password must not be empty");
        validateNotEmpty(host, "Host must not be empty");
        
        this.username = username;
        this.password = password;
        this.host = host;
        this.port = port;
        this.database = database;
        this.urlQuery = urlQuery;
        this.table = table;
        
        logger.debug("MetaKraftwerkMongoDB instance created with Host: " + host + ", Port: " + port + ", Database: " +
                    (database != null ? database : "admin"));
    }

    private void validateNotEmpty(String value, String message) {
        if (value == null || value.trim().isEmpty()) {
            logger.error("Validation error: " + message);
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Creates an SSLContext using the certificate(s) found in a PEM file.
     *
     * @param pemFilePath Path to the PEM file
     * @return SSLContext built from the certificate(s) in the PEM file
     * @throws Exception if an error occurs during SSLContext creation
     */
    private SSLContext createSSLContextFromPEM(String pemFilePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(new File(pemFilePath));
        @SuppressWarnings("unchecked")
        List<Certificate> certs = (List<Certificate>) certFactory.generateCertificates(fis);
        fis.close();
        
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        int certIndex = 1;
        for (Certificate cert : certs) {
            trustStore.setCertificateEntry("cert" + certIndex, cert);
            certIndex++;
        }
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    /**
     * Establishes a connection to the MongoDB database.
     * 
     * @throws MongoCommandException In case of connection errors
     */
    public void connect() throws MongoCommandException {
        logger.info("Starting connection to MongoDB at " + host + ":" + port);
        
        try {
            String currentDir = Paths.get("").toAbsolutePath().toString();
            String tlsCAFilePath = Paths.get(currentDir, "global-bundle.pem").toString();
            final SSLContext sslContextFinal;
            
            // Check if the CA file exists and create SSLContext from it
            File caFile = new File(tlsCAFilePath);
            if (caFile.exists()) {
                logger.info("Found TLS CA File at: " + tlsCAFilePath);
                sslContextFinal = createSSLContextFromPEM(tlsCAFilePath);
                logger.info("Successfully created SSLContext from PEM file.");
            } else {
                logger.warn("TLS CA File not found at: " + tlsCAFilePath);
                sslContextFinal = null;
            }
            
            MongoCredential credential = MongoCredential.createCredential(
                username, 
                (database != null && !database.isEmpty()) ? database : "admin", 
                password.toCharArray()
            );
            
            MongoClientSettings.Builder settingsBuilder = MongoClientSettings.builder()
                .credential(credential)
                .applyToSslSettings(builder -> {
                    builder.enabled(true);
                    builder.invalidHostNameAllowed(true);
                    if (sslContextFinal != null) {
                        builder.context(sslContextFinal);
                    }
                })
                .applyToClusterSettings(builder -> 
                    builder.hosts(Collections.singletonList(new ServerAddress(host, port)))
                );
            
            MongoClientSettings settings = settingsBuilder.build();
            
            this.mongoClient = MongoClients.create(settings);
            this.mongoDatabase = mongoClient.getDatabase((database != null && !database.isEmpty()) ? database : "admin");
            
            logger.info("Database connection successfully established");
            
        } catch (Exception e) {
            logger.error("Error connecting to MongoDB: " + e.getMessage(), e);
            // Optionally: rethrow as MongoCommandException if desired
        }
    }

    /**
     * Checks if an active database connection exists.
     */
    public boolean isConnected() {
        boolean isConnected = mongoClient != null && mongoDatabase != null;

        logger.debug("Connection status checked: " + (isConnected ? "connected." : "not connected."));

        return isConnected;
    }

    private String repeatString(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    public List<HashMap<String, String>> read(String collectionName, Document query) {
        List<HashMap<String, String>> results = new ArrayList<>();
        if (!isConnected()) {
            logger.error("No active database connection available.");
            return results;
        }
        
        if (query == null) {
            query = new Document();
        }
        
        logger.info("Executing MongoDB query on collection: " + collectionName);
        logger.debug("Query: " + query.toJson());
        
        try {
            long startTime = System.currentTimeMillis();
            MongoCollection<Document> collection = mongoDatabase.getCollection(collectionName);
            MongoCursor<Document> cursor = collection.find(query).iterator();
            boolean printed = false;
            while (cursor.hasNext()) {
                Document doc = cursor.next();
                HashMap<String, String> row = new HashMap<>();
                for (Map.Entry<String, Object> entry : doc.entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    String stringValue = (value != null) ? value.toString() : null;
                    row.put(key, stringValue);
                    if (!printed) {
                        System.out.println(key + " : String");
                    }
                }
                printed = true;
                results.add(row);
            }
            cursor.close();
            long endTime = System.currentTimeMillis();
            logger.info("Query completed. " + results.size() + " documents read in " + (endTime - startTime) + " ms");
        } catch (Exception e) {
            logger.error("Error reading documents: " + e.getMessage(), e);
        }
        
        System.out.println("Collection iteration completed.");
        return results;
    }

    /**
     * Executes a MongoDB query based on a query string.
     */
    public List<HashMap<String, String>> executeQuery(String queryStr) {
        if (!isConnected()) {
            logger.error("No active database connection available.");
            return new ArrayList<>();
        }
        
        logger.info("Processing query: " + queryStr);
        try {
            String collectionName = extractCollectionFromQuery(queryStr);
            logger.debug("Extracted collection name: " + collectionName);
            Document query = new Document();
            return read(collectionName, query);
        } catch (Exception e) {
            logger.error("Error processing from query: " + e.getMessage(), e);
            return new ArrayList<>();
        }
    }
    
    /**
     * Extracts the collection name from a query string.
     */
    private String extractCollectionFromQuery(String queryStr) {
        if (queryStr == null || queryStr.trim().isEmpty()) {
            return "";
        }
        
        String lowerQuery = queryStr.toLowerCase().trim();
        int fromIndex = lowerQuery.indexOf("from");
        if (fromIndex < 0) {
            return queryStr.trim();
        }
        
        String afterFrom = queryStr.substring(fromIndex + 4).trim();
        int spaceIndex = afterFrom.indexOf(' ');
        return (spaceIndex < 0) ? afterFrom : afterFrom.substring(0, spaceIndex);
    }
    
    /**
     * Executes the default query for the table specified in the constructor.
     */
    public List<HashMap<String, String>> readCollection() {
        logger.info("Executing default query: " + table);
        return executeQuery(this.table);
    }

    /**
     * Outputs the results of a collection query to the console.
     */
    public void print(String collectionName, Document query) {
        if (!isConnected()) {
            logger.error("No active database connection available.");
            return;
        }
        
        logger.info("Executing MongoDB query for console output on collection: " + collectionName);
        try {
            if (query == null) {
                query = new Document();
            }
            
            MongoCollection<Document> collection = mongoDatabase.getCollection(collectionName);
            List<Document> documents = collection.find(query).into(new ArrayList<>());
            if (documents.isEmpty()) {
                System.out.println("No documents found.");
                return;
            }
            
            Set<String> allFields = new HashSet<>();
            for (Document doc : documents) {
                allFields.addAll(doc.keySet());
            }
            List<String> sortedFields = new ArrayList<>(allFields);
            Collections.sort(sortedFields);
            
            System.out.println("\n----- QUERY RESULTS -----");
            System.out.println("Collection: " + collectionName);
            System.out.println("Total documents: " + documents.size());
            int docNum = 1;
            for (Document doc : documents) {
                System.out.println("\nDocument " + docNum + ":");
                System.out.println(repeatString("-", 40));
                for (String field : sortedFields) {
                    Object value = doc.get(field);
                    System.out.println("  " + field + ": " + (value != null ? value.toString() : "NULL"));
                }
                docNum++;
            }
            System.out.println("\n" + repeatString("-", 40));
            System.out.println("End of results");
            System.out.println("-------------------------\n");
            logger.info("Query results successfully displayed. " + documents.size() + " documents.");
        } catch (Exception e) {
            logger.error("Error executing query: " + e.getMessage(), e);
        }
    }


    /**
     * Closes the database connection.
     */
    public void close() {
        if (mongoClient != null) {
            try {
                mongoClient.close();
                mongoClient = null;
                mongoDatabase = null;
                logger.info("Database connection successfully closed.");
            } catch (Exception e) {
                logger.error("Error closing database connection: " + e.getMessage(), e);
            }
        } else {
            logger.debug("No connection to close.");
        }
    }

    /**
     * Encrypts a value using AES encryption and PBKDF2 key derivation.
     */
    public static String encrypt(String valueToEncrypt) {
        if (valueToEncrypt == null) {
            logger.warn("Encryption error: Input value is null");
            return null;
        }
        
        try {
            logger.debug("Starting encryption of a value with " + valueToEncrypt.length() + " characters");
            byte[] salt = new byte[16];
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), salt, 65536, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(valueToEncrypt.getBytes());
            String result = Base64.getEncoder().encodeToString(encryptedBytes);
            logger.debug("Encryption successfully completed");
            return result;
        } catch (Exception e) {
            logger.error("Encryption error: " + e.getMessage(), e);
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts a Base64-encoded string that was encrypted with the encrypt method.
     */
    public static String decrypt(String encryptedValue) {
        if (encryptedValue == null) {
            logger.warn("Decryption error: Input value is null");
            return null;
        }
        
        try {
            logger.debug("Starting decryption of a Base64 value");
            byte[] salt = new byte[16];
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), salt, 65536, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
            String result = new String(decryptedBytes);
            logger.debug("Decryption successfully completed");
            return result;
        } catch (Exception e) {
            logger.error("Decryption error: " + e.getMessage(), e);
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Outputs the contents of a HashMap result list formatted to the console.
     */
    public void printResults(List<HashMap<String, String>> results) {
        if (results == null || results.isEmpty()) {
            System.out.println("No results to display.");
            logger.info("No results available for display");
            return;
        }
        
        logger.debug("Displaying " + results.size() + " result rows on the console");
        System.out.println("\n----- QUERY RESULTS -----");
        System.out.println("Total rows: " + results.size());
        
        List<String> allKeys = new ArrayList<>();
        for (HashMap<String, String> row : results) {
            for (String key : row.keySet()) {
                if (!allKeys.contains(key)) {
                    allKeys.add(key);
                }
            }
        }
        
        System.out.println("\nColumns: " + String.join(", ", allKeys));
        System.out.println(repeatString("-", 80));
        
        int rowNum = 1;
        for (HashMap<String, String> row : results) {
            System.out.println("Row " + rowNum + ":");
            for (String key : allKeys) {
                String value = row.get(key);
                System.out.println("  " + key + ": " + (value != null ? value : "NULL"));
            }
            System.out.println(repeatString("-", 40));
            rowNum++;
        }
        
        System.out.println("-------------------------\n");
        logger.debug("Results output completed");
    }

    /**
     * Example for using the MetaKraftwerkMongoDB class.
     */
    public static void main(String[] args) {
        BasicConfigurator.configure();
        
        String username = "nompower-read-only-cons";
        String password = "fgJwu59Lnfb+jN37fbJq";
        String host = "nlb-internal-13c771e0008a7405.elb.eu-central-1.amazonaws.com";
        int port = 27017;
        String portStr = "27017"; // Kept for backward compatibility
        String database = "nompower";
        
        String currentDir = Paths.get("").toAbsolutePath().toString();
        System.out.println("Current working directory: " + currentDir);
        
        String tlsCAFilePath = "global-bundle.pem"; // Assuming file is in the current directory
        String urlQuery = "tls=true&tlsAllowInvalidHostnames=true&tlsCAFile=" + tlsCAFilePath;
        
        String table = "select * from nompower_deal";
        
        logger.info("Starting MetaKraftwerkMongoDB application");
        
        try {
            MetaKraftwerkMongoDB db = new MetaKraftwerkMongoDB(
                username, password, host, port, portStr, database, urlQuery, table);
            
            db.connect();
            
            System.out.println("Executing query...");
            List<HashMap<String, String>> results = db.readCollection();
            System.out.println("Retrieved " + results.size() + " rows");
            
            db.printResults(results);
            
            db.close();
            logger.info("application successfully completed");
            
        } catch (MongoCommandException m) {
            logger.error("MongoDB command error", m);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Unexpected error in application", e);
        }
    }
}
