package keycloak.auth.nostr;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class NostrIdentityProvider extends AbstractIdentityProvider<IdentityProviderModel> {
    private static final long LIFETIME = 180;
    private static final SecureRandom RANDOM = new SecureRandom();

    public NostrIdentityProvider(KeycloakSession session, IdentityProviderModel config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        var auth = request.getAuthenticationSession();
        if (auth == null || request.getState() == null) return invalid(auth);

        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String nonce = HexFormat.of().formatHex(bytes);
        String verifyUrl = UriBuilder.fromUri(request.getRedirectUri()).path("verify").build().toASCIIString();
        auth.setAuthNote(note(), nonce);
        session.singleUseObjects().put(key("pending", nonce), LIFETIME, Map.of(
                "url", verifyUrl, "expires", Long.toString(now() + LIFETIME)));

        return session.getProvider(LoginFormsProvider.class).setAuthenticationSession(auth)
                .setAttribute("brokerState", request.getState().getEncoded())
                .setAttribute("brokerNonce", nonce)
                .setAttribute("authorizationOrigins", getConfig().getConfig()
                        .getOrDefault(NostrIdentityProviderFactory.AUTHORIZATION_ORIGINS, ""))
                .setAttribute("verifyUrl", verifyUrl)
                .setAttribute("finishUrl", UriBuilder.fromUri(request.getRedirectUri()).path("finish").build())
                .createForm("kc-nostr-auth.ftl");
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(this, callback);
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity,
                                  UserSessionModel userSession, UserModel user) {
        return retrieveToken(session, identity);
    }

    private Response invalid(AuthenticationSessionModel auth) {
        return ErrorPage.error(session, auth, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    private String note() {
        return "keycloak.auth.nostr." + getConfig().getAlias();
    }

    private String key(String purpose, String token) {
        return note() + ":" + session.getContext().getRealm().getId() + ":" + purpose + ":" + token;
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    @Provider
    @Vetoed // The broker constructs this resource with the active provider and callback.
    public static final class Endpoint {
        private final NostrIdentityProvider provider;
        private final AuthenticationCallback callback;

        Endpoint(NostrIdentityProvider provider, AuthenticationCallback callback) {
            this.provider = provider;
            this.callback = callback;
        }

        @POST
        @Path("verify")
        @Consumes(MediaType.TEXT_PLAIN)
        public Response verify(@HeaderParam("Authorization") String authorization, InputStream input) throws IOException {
            byte[] body = input.readNBytes(65);
            String nonce = new String(body, StandardCharsets.US_ASCII);
            if (!Nip98.NONCE.matcher(nonce).matches()) return verification(false);

            var objects = provider.session.singleUseObjects();
            String pendingKey = provider.key("pending", nonce);
            var pending = objects.get(pendingKey);
            if (pending == null) return verification(false);

            String actualUrl = provider.session.getContext().getUri().getRequestUri().toASCIIString();
            if (!actualUrl.equals(pending.get("url"))) return verification(false);

            long expiresAt = Long.parseLong(pending.get("expires"));
            long now = now();
            if (expiresAt <= now) return verification(false);
            String address = provider.session.getContext().getConnection().getRemoteAddr();
            if (!VerificationRateLimit.allow(objects, provider.key("rate-address", address),
                    provider.key("rate-challenge", nonce), now, expiresAt)) {
                return Response.status(429).header("Cache-Control", "no-store").build();
            }
            String pubkey = Nip98.verifiedPublicKey(authorization, actualUrl, body, now());
            if (pubkey == null || objects.remove(pendingKey) == null) return verification(false);

            long remaining = expiresAt - now();
            if (remaining <= 0) return verification(false);
            objects.put(provider.key("ready", nonce), remaining, Map.of("subject", pubkey));
            return verification(true);
        }

        @POST
        @Path("finish")
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public Response finish(@FormParam("state") String state, @FormParam("nonce") String nonce) {
            if (state == null || nonce == null || !Nip98.NONCE.matcher(nonce).matches()) return provider.invalid(null);
            var auth = callback.getAndVerifyAuthenticationSession(state);
            if (!nonce.equals(auth.getAuthNote(provider.note()))) return provider.invalid(auth);
            var proof = provider.session.singleUseObjects().remove(provider.key("ready", nonce));
            if (proof == null) return provider.invalid(auth);

            provider.session.getContext().setAuthenticationSession(auth);
            auth.removeAuthNote(provider.note());
            String subject = proof.get("subject");
            var identity = new BrokeredIdentityContext(subject, provider.getConfig());
            identity.setUsername("nostr-" + subject);
            identity.setIdp(provider);
            identity.setAuthenticationSession(auth);
            return callback.authenticated(identity);
        }

        private static Response verification(boolean success) {
            return Response.status(success ? 204 : 401).header("Cache-Control", "no-store").build();
        }
    }
}
