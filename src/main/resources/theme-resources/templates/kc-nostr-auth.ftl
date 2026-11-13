<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section == "header">
    ${msg("nostrAuthTitle")}
  <#elseif section == "form">
    <form id="kc-nostr-auth" method="post" action="${finishUrl}" data-verify="${verifyUrl}"
          data-missing="${msg('nostrAuthMissing')}" data-failed="${msg('nostrAuthFailed')}"
          data-signing="${msg('nostrAuthSigning')}" data-rate-limited="${msg('nostrAuthRateLimited')}"
          data-authorization-origins="${authorizationOrigins!}">
      <p>${msg("nostrAuthInstructions")}</p>
      <input type="hidden" name="state" value="${brokerState}">
      <input type="hidden" name="nonce" value="${brokerNonce}">
      <button id="kc-nostr-auth-browser" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="button" disabled>
        ${msg("nostrAuthSign")}
      </button>
      <details>
        <summary>${msg("nostrAuthRemote")}</summary>
        <label for="kc-nostr-auth-bunker">${msg("nostrAuthBunker")}</label>
        <input id="kc-nostr-auth-bunker" type="password" placeholder="bunker://…" autocomplete="off"
               spellcheck="false" maxlength="4096">
        <button id="kc-nostr-auth-remote" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" type="button" disabled>
          ${msg("nostrAuthConnect")}
        </button>
        <a id="kc-nostr-auth-authorize" target="_blank" rel="noopener noreferrer" hidden>
          ${msg("nostrAuthAuthorize")} <bdi id="kc-nostr-auth-authorize-origin"></bdi>
        </a>
        <p id="kc-nostr-auth-authorize-blocked" role="status" hidden>${msg("nostrAuthAuthorizationBlocked")}</p>
      </details>
      <p role="status" id="kc-nostr-auth-status" aria-live="polite"></p>
    </form>
    <p><a href="${url.loginRestartFlowUrl}">${msg("backToLogin")}</a></p>
    <script type="module" src="${url.resourcesPath}/js/kc-nostr-auth.js"></script>
  </#if>
</@layout.registrationLayout>
