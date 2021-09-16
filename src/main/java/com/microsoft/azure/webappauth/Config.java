// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.webappauth;

/**
 * Application`s OIDC configuration to be used with Microsoft Identity Platform
 */
public class Config {

    private String clientId;

    private String authority;

    private String redirectURI;

    private String scope;

    private String secret;

    public String getClientId() {
        return clientId;
    }

    public String getAuthority() {
        return authority;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getScope() {
        return scope;
    }

    public String getSecret() {
        return secret;
    }
}
