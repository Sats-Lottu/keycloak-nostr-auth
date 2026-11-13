package keycloak.auth.nostr;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;

final class Nip98 {
    static final Pattern NONCE = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SIGNATURE = Pattern.compile("[0-9a-f]{128}");
    private static final int KIND = 27235;
    private static final int CLOCK_WINDOW = 60;
    private static final String SCHEME = "Nostr ";
    private static final HexFormat HEX = HexFormat.of();
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(JsonWriteFeature.WRITE_HEX_UPPER_CASE)
            .build();

    private Nip98() {}

    static String verifiedPublicKey(String authorization, String url, byte[] body, long now) {
        if (authorization == null || authorization.length() > 8192 ||
                !authorization.regionMatches(true, 0, SCHEME, 0, SCHEME.length())) return null;

        try {
            JsonNode event = JSON.readTree(Base64.getDecoder().decode(authorization.substring(SCHEME.length())));
            if (event == null || !event.isObject()) return null;
            var kind = event.path("kind");
            var time = event.path("created_at");
            var content = event.path("content");
            if (!kind.isIntegralNumber() || !kind.canConvertToInt() || kind.intValue() != KIND ||
                    !time.isIntegralNumber() || !time.canConvertToLong() ||
                    time.longValue() < now - CLOCK_WINDOW || time.longValue() > now + CLOCK_WINDOW ||
                    !content.isTextual() || !content.textValue().isEmpty()) return null;

            var tags = event.path("tags");
            if (!validTags(tags, url, HEX.formatHex(Bip340.sha256(body)))) return null;

            String pubkey = event.path("pubkey").textValue();
            String id = event.path("id").textValue();
            String signature = event.path("sig").textValue();
            if (!matches(NONCE, pubkey) || !matches(NONCE, id) || !matches(SIGNATURE, signature)) return null;

            var canonical = JSON.createArrayNode().add(0).add(pubkey).add(time.longValue()).add(KIND);
            canonical.add(tags).add("");
            byte[] digest = Bip340.sha256(JSON.writeValueAsBytes(canonical));
            if (!MessageDigest.isEqual(digest, HEX.parseHex(id))) return null;

            return Bip340.verify(HEX.parseHex(pubkey), digest, HEX.parseHex(signature)) ? pubkey : null;
        } catch (IllegalArgumentException | IOException ex) {
            return null;
        }
    }

    private static boolean validTags(JsonNode tags, String url, String bodyHash) {
        if (!tags.isArray()) return false;
        String signedUrl = null;
        String method = null;
        String payload = null;
        for (var tag : tags) {
            if (!tag.isArray() || tag.isEmpty()) return false;
            for (var item : tag) {
                if (!item.isTextual()) return false;
            }
            switch (tag.get(0).textValue()) {
                case "u" -> {
                    if (signedUrl != null || tag.size() != 2) return false;
                    signedUrl = tag.get(1).textValue();
                }
                case "method" -> {
                    if (method != null || tag.size() != 2) return false;
                    method = tag.get(1).textValue();
                }
                case "payload" -> {
                    if (payload != null || tag.size() != 2) return false;
                    payload = tag.get(1).textValue();
                }
                default -> { }
            }
        }
        return url.equals(signedUrl) && "POST".equals(method) && bodyHash.equals(payload);
    }

    private static boolean matches(Pattern pattern, String value) {
        return value != null && pattern.matcher(value).matches();
    }
}
