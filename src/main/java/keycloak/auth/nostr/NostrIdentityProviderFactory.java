package keycloak.auth.nostr;

import java.util.List;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public final class NostrIdentityProviderFactory extends AbstractIdentityProviderFactory<NostrIdentityProvider> {
    static final String AUTHORIZATION_ORIGINS = "authorizationOrigins";

    @Override
    public String getId() {
        return "nostr";
    }

    @Override
    public String getName() {
        return "Nostr";
    }

    @Override
    public NostrIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new NostrIdentityProvider(session, model);
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new IdentityProviderModel();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(AUTHORIZATION_ORIGINS)
                .label("Trusted signer authorization origins")
                .helpText("Comma-separated HTTPS origins for remote signer authorization links. "
                        + "Leave empty to allow any HTTPS origin and display it before opening the link.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .build();
    }
}
