# Keycloak Nostr Auth

Provedor de identidade Keycloak para login e cadastro pela chave pública Nostr. O usuário pode assinar com uma extensão de navegador **NIP‑07** ou com um assinador remoto **NIP‑46** por URI `bunker://`.

Ambos os assinadores produzem um evento **NIP‑98** de tipo `27235`. O servidor valida o evento e a assinatura Schnorr conforme **NIP‑01** e **BIP340**, vincula a prova à URL, ao método POST e ao hash do desafio emitido para o navegador, e aceita a prova uma única vez. A janela de timestamp do evento é de 60 segundos em cada direção. O desafio expira em três minutos.

No fluxo NIP‑46, o navegador usa uma chave de transporte efêmera e mensagens **NIP‑44**. A mesma chave efêmera responde aos desafios **NIP‑42** do relay. O Keycloak usa como identificador a chave do evento assinado, que deve coincidir com a chave retornada por `get_public_key`. O assinador mantém a chave privada do usuário. O navegador recebe a URI de conexão e se conecta diretamente aos relays indicados nela.

## Instalação

Requisitos de build: Node.js 24, Java 21 e Maven. Compile o JavaScript antes de empacotar o JAR.

```sh
npm ci
npm run build
mvn verify
```

Copie `target/keycloak-nostr-auth-0.2.1.jar` para `/opt/keycloak/providers/` e execute `kc.sh build` antes de iniciar a imagem otimizada. Use o Keycloak **26.8.2** ou uma versão com as correções de segurança posteriores. Em **Identity providers**, adicione o provedor do tipo `nostr`. Mantenha **Trust Email** e **Store Tokens** desativados. O fluxo **First Broker Login** do realm controla criação, preenchimento de perfil e vinculação de contas. O JAR inclui os recursos necessários para usar o provedor com o tema padrão do Keycloak.

Sirva o Keycloak em HTTPS e configure o hostname público. Se a política CSP definir `connect-src`, permita a origem do Keycloak e os relays WebSocket seguros usados pelos assinadores remotos. O ambiente local usa HTTP e WebSocket na interface de loopback.

A página exibe a origem HTTPS antes de abrir a autorização solicitada pelo assinador remoto. Em implantações com assinadores conhecidos, configure **Trusted signer authorization origins** com as origens HTTPS separadas por vírgula, como `https://signer.example.org`. A comparação usa domínio e porta exatos. A lista vazia permite qualquer origem HTTPS. Em importações de realm, use `config.authorizationOrigins` no provedor de identidade.

O provedor permite até cinco verificações por desafio e vinte por IP em cada janela de dez segundos, por realm e alias. Ao esgotar as tentativas do desafio, volte à tela de login para iniciar outro. Se houver um proxy reverso, configure os cabeçalhos encaminhados e restrinja os proxies confiáveis para que o Keycloak identifique o IP correto.

## Testes

`npm test` verifica a política de destinos de autorização. `mvn verify` roda os vetores oficiais BIP340 e testa o limite de tentativas. Para validar a instalação, habilite o provedor em um realm com o tema padrão e conclua o login no navegador.

## Referências e licença

- [Keycloak Server Developer Guide](https://www.keycloak.org/docs/26.8.2/server_development/)
- [NIP‑01](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP‑07](https://github.com/nostr-protocol/nips/blob/master/07.md), [NIP‑42](https://github.com/nostr-protocol/nips/blob/master/42.md), [NIP‑44](https://github.com/nostr-protocol/nips/blob/master/44.md), [NIP‑46](https://github.com/nostr-protocol/nips/blob/master/46.md) e [NIP‑98](https://github.com/nostr-protocol/nips/blob/master/98.md)
- [BIP340 — Schnorr para secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

Código do projeto sob [licença MIT](LICENSE).

## Publicar uma versão

Atualize a versão em `pom.xml` e em `package.json` e `package-lock.json`. Depois que a alteração entrar em `main`, crie e envie uma tag anotada `vX.Y.Z` no commit da versão. O GitHub Actions valida a origem da tag, roda os testes e publica o JAR e seu `SHA256SUMS` em Releases.
