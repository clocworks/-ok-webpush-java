package com.clocworks.webpush.push;

import com.clocworks.encrypt.Encoding;
import com.clocworks.encrypt.Encrypted;
import com.clocworks.encrypt.Utils;
import com.clocworks.webpush.notification.Notification;
import okhttp3.*;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.jetbrains.annotations.NotNull;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.function.Consumer;


@SuppressWarnings("unused")
public class PushService extends AbstractPushService<PushService> {

    private final OkHttpClient client = new OkHttpClient();

    public PushService() {
    }

    public PushService(String gcmApiKey) {
        super(gcmApiKey);
    }

    public PushService(KeyPair keyPair) {
        super(keyPair);
    }

    public PushService(KeyPair keyPair, String subject) {
        super(keyPair, subject);
    }

    public PushService(String publicKey, String privateKey) throws GeneralSecurityException {
        super(publicKey, privateKey);
    }

    public PushService(String publicKey, String privateKey, String subject) throws GeneralSecurityException {
        super(publicKey, privateKey, subject);
    }

    /**
     * Send a notification and call the callbacks on response
     *
     * @param notification Notification to send
     * @param encoding     AESGCM or AES128GCM
     * @throws GeneralSecurityException possible exception
     * @throws IOException              If body read fail
     * @throws JoseException            If error creating VAPID
     */
    public void send(Notification notification, Encoding encoding, Consumer<Response> onResponse, Consumer<Throwable> onFailure) throws GeneralSecurityException, IOException, JoseException {

        client.newCall(prepareRequest(notification, encoding)).enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                onFailure.accept(e);
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                var body = response.body();
                if (body != null) System.out.println(body.string());
                else System.out.println("no body ");
                try (response; response) {
                    onResponse.accept(response);
                }
            }
        });
    }

    public void send(Notification notification, Consumer<Response> onResponse, Consumer<Throwable> onFailure) throws JoseException, GeneralSecurityException, IOException {
        send(notification, Encoding.AESGCM, onResponse, onFailure);
    }

    /**
     * Send a notification and wait for the response.
     *
     * Warning: The response must be closed after receipt
     * @param notification Notification to send
     * @param encoding     AESGCM or AES128GCM
     * @throws GeneralSecurityException possible exception
     * @throws IOException              If body read fail
     * @throws JoseException            If error creating VAPID
     * @return Response containing body and headers of response
     */
    public Response send(Notification notification, Encoding encoding) throws JoseException, GeneralSecurityException, IOException {
        return client.newCall(prepareRequest(notification, encoding)).execute();
    }

    public Response send(Notification notification) throws JoseException, GeneralSecurityException, IOException {
        return send(notification, Encoding.AESGCM);
    }

    private Request prepareRequest(Notification notification, Encoding encoding) throws GeneralSecurityException, IOException, JoseException {

        Request.Builder request = new Request.Builder();


        if (getPrivateKey() != null && getPublicKey() != null) {
            if (!Utils.verifyKeyPair(getPrivateKey(), getPublicKey())) {
                throw new IllegalStateException("Public key and private key do not match.");
            }
        }

        Encrypted encrypted = encrypt(
                notification.getPayload(),
                notification.getUserPublicKey(),
                notification.getUserAuth(),
                encoding
        );

        byte[] dh = Utils.encode((ECPublicKey) encrypted.getPublicKey());
        byte[] salt = encrypted.getSalt();

        String url = notification.getEndpoint();
        Headers.Builder headers = new Headers.Builder();


        headers.add("TTL", String.valueOf(notification.getTTL()));


        if (notification.hasUrgency()) {
            headers.add("Urgency", notification.getUrgency().getHeaderValue());
        }

        if (notification.hasTopic()) {
            headers.add("Topic", notification.getTopic());
        }


        if (notification.hasPayload()) {
            request.header("Content-Type", "application/octet-stream");

            if (encoding == Encoding.AES128GCM) {
                headers.add("Content-Encoding", "aes128gcm");
            } else if (encoding == Encoding.AESGCM) {
                headers.add("Content-Encoding", "aesgcm");
                headers.add("Encryption", "salt=" + Base64.getUrlEncoder().withoutPadding().encodeToString(salt));
                headers.add("Crypto-Key", "dh=" + Base64.getUrlEncoder().encodeToString(dh));
            }

            RequestBody requestBody = RequestBody.create(encrypted.getCiphertext());
            request.post(requestBody);

        }

        if (notification.isGcm()) {
            if (getGcmApiKey() == null) {
                throw new IllegalStateException("An GCM API key is needed to send a push notification to a GCM endpoint.");
            }

            headers.add("Authorization", "key=" + getGcmApiKey());
        } else if (vapidEnabled()) {
            if (encoding == Encoding.AES128GCM) {
                if (notification.getEndpoint().startsWith("https://fcm.googleapis.com")) {
                    url = notification.getEndpoint().replace("fcm/send", "wp");
                }
            }

            JwtClaims claims = new JwtClaims();
            claims.setAudience(notification.getOrigin());
            claims.setExpirationTimeMinutesInTheFuture(12 * 60);
            if (getSubject() != null) {
                claims.setSubject(getSubject());
            }

            JsonWebSignature jws = new JsonWebSignature();
            jws.setHeader("typ", "JWT");
            jws.setHeader("alg", "ES256");
            jws.setPayload(claims.toJson());
            jws.setKey(getPrivateKey());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

            byte[] pk = Utils.encode((ECPublicKey) getPublicKey());

            if (encoding == Encoding.AES128GCM) {
                headers.add("Authorization", "vapid t=" + jws.getCompactSerialization() + ", k=" + Base64.getUrlEncoder().withoutPadding().encodeToString(pk));
            } else if (encoding == Encoding.AESGCM) {
                headers.add("Authorization", "WebPush " + jws.getCompactSerialization());

            }

            if (headers.get("Crypto-Key") != null) {
                headers.add("Crypto-Key", headers.get("Crypto-Key") + ";p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            } else {
                headers.add("Crypto-Key", "p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            }
        } else if (notification.isFcm() && getGcmApiKey() != null) {
            request.addHeader("Authorization", "key=" + getGcmApiKey());
        }

        return request
                .url(url)
                .headers(headers.build())
                .build();

    }

}
