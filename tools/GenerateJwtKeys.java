import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Base64;

// Run from the authentication-service root. Existing keys are validated and preserved.
public class GenerateJwtKeys {
    public static void main(String[] args) throws Exception {
        Path directory = Path.of("secrets");
        Files.createDirectories(directory);
        Path privateFile = directory.resolve("private-key.pem");
        Path publicFile = directory.resolve("public-key.pem");
        if (Files.exists(privateFile) && Files.exists(publicFile)) {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(readPem(privateFile, "PRIVATE KEY")));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(readPem(publicFile, "PUBLIC KEY")));
            if (!privateKey.getModulus().equals(publicKey.getModulus())
                    || publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("Existing RSA keys do not form a valid 2048+ bit pair");
            }
            System.out.println("Existing RSA keys are valid and were preserved.");
            return;
        }
        if (Files.exists(privateFile) || Files.exists(publicFile)) {
            throw new IllegalStateException("Only one RSA key exists. Restore its matching key; no files were overwritten.");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Files.writeString(privateFile, pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
                StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
        Files.writeString(publicFile, pem("PUBLIC KEY", pair.getPublic().getEncoded()),
                StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
        System.out.println("Created RSA keys in secrets/. Keep this pair between restarts.");
    }

    private static byte[] readPem(Path file, String type) throws Exception {
        String encoded = Files.readString(file).replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(encoded);
    }

    private static String pem(String type, byte[] bytes) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n";
    }
}
