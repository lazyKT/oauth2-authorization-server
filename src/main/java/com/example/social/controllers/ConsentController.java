package com.example.social.controllers;


import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
public class ConsentController {

    private final OAuth2AuthorizationConsentService consentService;


    public ConsentController (OAuth2AuthorizationConsentService service) {
        this.consentService = service;
    }


    @GetMapping("/oauth2/consent")
    public String consent (
        Principal principal,
        Model model,
        @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
        @RequestParam(OAuth2ParameterNames.STATE) String state
    ) {
        Set<String> scopesToApproved = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();
        // Check if the consent is agreed in previous sessions
        OAuth2AuthorizationConsent previousConsent = this.consentService.findById(clientId, principal.getName());
        for (String scopeFromRequest: StringUtils.delimitedListToStringArray(scope, " ")) {
            if (previousConsent != null && previousConsent.getScopes().contains(scopeFromRequest)) {
                previouslyApprovedScopes.add(scopeFromRequest);
            } else {
                scopesToApproved.add(scopeFromRequest);
            }
        }

        // Pass values to template
        model.addAttribute("state", state);
        model.addAttribute("clientId", clientId);
        model.addAttribute("scopes", withDescription(scopesToApproved));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());

        return "oauth2/consent";
    }


    private Set<ScopeWithDescription> withDescription (Set<String> scopes) {
        return scopes.stream().map(ScopeWithDescription::new).collect(Collectors.toSet());
    }


    private static class ScopeWithDescription {
        public final String scope;
        public final String description;

        private final static String defaultDescription =
                "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";

        private static final Map<String, String> scopeDescriptions = new HashMap<>();
        static {
            scopeDescriptions.put(
                    "openid",
                    "use openidc to verify your identity"
            );
            scopeDescriptions.put(
                    "profile",
                    "profile information for personalization"
            );
            scopeDescriptions.put(
                    "email",
                    "email address"
            );
        }

        ScopeWithDescription (String _scope) {
            this.scope = _scope;
            this.description = scopeDescriptions.getOrDefault(_scope, defaultDescription);
        }

    }
}
