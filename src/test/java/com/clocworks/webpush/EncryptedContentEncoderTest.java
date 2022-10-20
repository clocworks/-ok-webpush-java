package com.clocworks.webpush;

import com.clocworks.encrypt.EncryptedContentEncoder;
import com.clocworks.encrypt.Utils;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.Base64;
import java.util.HashMap;

import static com.clocworks.encrypt.Encoding.AES128GCM;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class EncryptedContentEncoderTest {
    @BeforeAll
    public static void addSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private byte[] decode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    @Test
    public void testZeroSaltAndKey() throws GeneralSecurityException {
        EncryptedContentEncoder encryptedContentEncoder = new EncryptedContentEncoder();
        String plaintext = "Hello";
        byte[] salt = new byte[16];
        byte[] key = new byte[16];
        byte[] actual = encryptedContentEncoder.encrypt(plaintext.getBytes(), salt, key, null, null, null, AES128GCM);
        byte[] expected = decode("AAAAAAAAAAAAAAAAAAAAAAAAEAAAMpsi6NfZUkOdJI96XyX0tavLqyIdiw");

        assertArrayEquals(expected, actual);
    }

    /**
     * See https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09#section-3.1
     *
     * - Record size is 4096.
     * - Input keying material is identified by an empty string.
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void testSampleEncryption() throws GeneralSecurityException {
        EncryptedContentEncoder encryptedContentEncoder = new EncryptedContentEncoder();

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode("I1BsxtFttlv3u_Oo94xnmw");
        byte[] key = decode("yqdlZ-tYemfogSmv7Ws5PQ");
        byte[] actual = encryptedContentEncoder.encrypt(plaintext, salt, key, null, null, null, AES128GCM);
        byte[] expected = decode("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testSampleEncryptDecrypt() throws GeneralSecurityException {
        String encodedKey = "yqdlZ-tYemfogSmv7Ws5PQ";
        String encodedSalt = "I1BsxtFttlv3u_Oo94xnmw";

        // Prepare the key map, which maps a keyid to a keypair.
        PrivateKey privateKey = Utils.loadPrivateKey(encodedKey);
        PublicKey publicKey = Utils.loadPublicKey((ECPrivateKey) privateKey);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        HashMap<String, KeyPair> keys = new HashMap<>();
        keys.put("", keyPair);

        HashMap<String, String> labels = new HashMap<>();
        labels.put("", "P-256");

        // Run the encryption and decryption
        EncryptedContentEncoder encryptedContentEncoder = new EncryptedContentEncoder(keys, labels);

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode(encodedSalt);
        byte[] key = decode(encodedKey);
        byte[] ciphertext = encryptedContentEncoder.encrypt(plaintext, salt, key, null, null, null, AES128GCM);
        byte[] decrypted = encryptedContentEncoder.decrypt(ciphertext, null, key, null, AES128GCM);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * See https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09#section-3.2
     *
     * TODO: This test is disabled because the library does not deal with multiple records yet.
     *
     * @throws GeneralSecurityException
     */
    @Test
    @Disabled
    public void testEncryptionWithMultipleRecords() throws GeneralSecurityException {
        EncryptedContentEncoder encryptedContentEncoder = new EncryptedContentEncoder();

        byte[] plaintext = "I am the walrus".getBytes();
        byte[] salt = decode("uNCkWiNYzKTnBN9ji3-qWA");
        byte[] key = decode("BO3ZVPxUlnLORbVGMpbT1Q");
        byte[] actual = encryptedContentEncoder.encrypt(plaintext, salt, key, null, null, null, AES128GCM);
        byte[] expected = decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");

        assertArrayEquals(expected, actual);
    }
}
