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

    private String postLogoutURI;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getPostLogoutURI() {
        return postLogoutURI;
    }

    public void setPostLogoutURI(String postLogoutURI) {
        this.postLogoutURI = postLogoutURI;
    }
}
