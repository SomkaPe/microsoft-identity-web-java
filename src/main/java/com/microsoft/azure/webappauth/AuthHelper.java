// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.webappauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static com.microsoft.azure.webappauth.Constants.FAILED_TO_VALIDATE_MESSAGE;

/**
 * Helper class to be used to simplify integration of
 * java mvc web applications with Microsoft Identity Platform
 */
public class AuthHelper {
    private final String LOG_OUT_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";
    private final String LOG_OUT_URL_WITH_REDIRECT_FORMAT = LOG_OUT_URL + "?post_logout_redirect_uri=%s";

    static final String STATE_PARAMETER = "state";
    static final String NONCE_CLAIM = "nonce";

    private Config config;

    public AuthHelper(Config config) {
        this.config = config;
    }

    public AuthHelper(String configJson) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();

        Config config = objectMapper.readValue(configJson, Config.class);

        this.config = config;
    }

    /**
     * Processing of auth code redirect request from identity provider includes:
     *  - validation of auth code redirect request
     *  - redeeming of auth code for auth tokens with identity provider
     *  - persistence of OIDC tokens and user credential in the user`s session
     * @param request auth code redirect request from identity provider
     */
    public void processAuthCodeRedirectRequest(HttpServletRequest request) throws Throwable {
        HttpSession session = request.getSession();

        // validate that state in response equals to state in request stored previously in the session
        SessionHelper.validateState(session, request.getParameter(STATE_PARAMETER));

        AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(getFullURL(request)));

        if (authResponse instanceof AuthenticationSuccessResponse) {
            AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;

            // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
            validateAuthRespMatchesAuthCodeFlow(oidcResponse);

            IConfidentialClientApplication app = createClientApplication();

            IAuthenticationResult result = getAuthResultByAuthCode(
                    oidcResponse.getAuthorizationCode().getValue(),
                    app);

            // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
            SessionHelper.validateNonce(session, getNonceClaimValueFromIdToken(result.idToken()));

            SessionHelper.setSessionPrincipal(session, result);
            SessionHelper.setTokenCache(session, app.tokenCache().serialize());
        } else {
            AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
            throw new Exception(String.format("Request for auth code failed: %s - %s",
                    oidcResponse.getErrorObject().getCode(),
                    oidcResponse.getErrorObject().getDescription()));
        }
    }

    private String getNonceClaimValueFromIdToken(String idToken) throws ParseException {
        return (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim(NONCE_CLAIM);
    }

    private IAuthenticationResult getAuthResultByAuthCode(
            String authorizationCode,
            IConfidentialClientApplication app) throws Throwable {

            AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                    authorizationCode,
                    new URI(config.getRedirectURI())).
                    build();

            return app.acquireToken(parameters).get();
    }

    private ConfidentialClientApplication createClientApplication() throws MalformedURLException {
        return ConfidentialClientApplication.builder
                (config.getClientId(), ClientCredentialFactory.createFromSecret(config.getSecret()))
                .authority(config.getAuthority())
                .build();
    }

    private void validateAuthRespMatchesAuthCodeFlow(AuthenticationSuccessResponse oidcResponse) throws Exception {
        String authCode = oidcResponse.getAuthorizationCode().getValue();
        if (StringUtils.isBlank(authCode)) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "empty or null auth code received");
        }
    }

    /**
     * Check that current user`s session is authenticated,
     * which means that user`s credential is attached to the session
     * and it is not expired,
     * If id token is expired try to acquire new one using RT
     * @param request
     * @return boolean
     */
    public boolean isSessionAuthenticated(HttpServletRequest request) throws MalformedURLException {
        HttpSession session = request.getSession();

        IAuthenticationResult credential = SessionHelper.getSessionPrincipal(session);
        if(credential == null){
            return false;
        }
        if(isValid(credential)){
            return true;
        }

        String tokenCache = SessionHelper.getTokenCache(session);
        if(StringUtils.isNoneBlank(tokenCache)){
            IConfidentialClientApplication app = createClientApplication();

            app.tokenCache().deserialize(tokenCache);

            IAuthenticationResult refreshedCredential = null;

            try {
                refreshedCredential = refreshCredential(app, credential);
                if(isValid(refreshedCredential)){
                    SessionHelper.setSessionPrincipal(session, refreshedCredential);
                    SessionHelper.setTokenCache(session, app.tokenCache().serialize());

                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    /**
     * Refresh credential using refresh token code flow
     * @param app
     * @param credential
     * @return
     * @throws MalformedURLException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    private IAuthenticationResult refreshCredential
            (IConfidentialClientApplication app, IAuthenticationResult credential)
            throws MalformedURLException, ExecutionException, InterruptedException {

            return getTokenSilently(app, credential, config.getScope());
    }

    private IAuthenticationResult getTokenSilently
            (IConfidentialClientApplication app, IAuthenticationResult credential, String scope)
            throws MalformedURLException, ExecutionException, InterruptedException {

        SilentParameters parameters = SilentParameters.builder(
                Collections.singleton(scope),
                credential.account()).build();

        return app.acquireTokenSilently(parameters).get();
    }

    private boolean isValid(IAuthenticationResult credential){
        if(credential == null){
            return false;
        }
        if(credential.idToken() == null
                || credential.accessToken() == null
                || credential.account() == null){
            return false;
        }

        if(credential.expiresOnDate().before(new Date())){
            return false;
        }

        return true;
    }


    /**
     * Acquire access token for the scope from Microsoft identity platform
     * using user`s credential attached to the session
     * @param scope
     * @return
     */
    public String getAccessToken(String scope, HttpServletRequest request) throws MalformedURLException {
        HttpSession session = request.getSession();

        IAuthenticationResult credential = SessionHelper.getSessionPrincipal(session);
        if(credential == null){
            return null;
        }

        String tokenCache = SessionHelper.getTokenCache(session);
        if(StringUtils.isNoneBlank(tokenCache)){
            IConfidentialClientApplication app = createClientApplication();

            app.tokenCache().deserialize(tokenCache);

            try {
                IAuthenticationResult authResult = getTokenSilently(app, credential, scope);
                if(authResult != null && StringUtils.isNoneBlank(authResult.accessToken())){
                    SessionHelper.setTokenCache(session, app.tokenCache().serialize());

                    return authResult.accessToken();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * Return user`s credential attached to the session
     * @return
     */
    public IAuthenticationResult getCredential(HttpServletRequest request){
        return SessionHelper.getSessionPrincipal(request.getSession());
    }

    /**
     * Return authorization url to be used to redirect user to identity provider
     * to perform authorization
     * @return
     */
    public String getAuthorizationUrl(HttpServletRequest request) throws MalformedURLException {

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        SessionHelper.addStateNonceToSession(request.getSession(), state, nonce);

        PublicClientApplication pca = PublicClientApplication
                .builder(config.getClientId()).authority(config.getAuthority())
                .build();

        String scopeParameter = StringUtils.isBlank(config.getScope()) ? "" : config.getScope();

        AuthorizationRequestUrlParameters parameters =
                AuthorizationRequestUrlParameters
                        .builder(config.getRedirectURI(),
                                Collections.singleton(scopeParameter))
                        .responseMode(ResponseMode.QUERY)
                        .prompt(Prompt.SELECT_ACCOUNT)
                        .state(state)
                        .nonce(nonce)
                        .build();

        return pca.getAuthorizationRequestUrl(parameters).toString();
    }

    private String getFullURL(HttpServletRequest request){
        String currentUri = request.getRequestURL().toString();
        String queryStr = request.getQueryString();

        return currentUri + (queryStr != null ? "?" + queryStr : "");
    }

    /**
     * Return authorization url to be used to redirect user to identity provider
     * to invalidate user`s session
     * @return
     */
    public String getLogOutUrl() throws UnsupportedEncodingException {
        if(StringUtils.isNoneBlank(config.getPostLogoutURI())){
            return String.format
                    (LOG_OUT_URL_WITH_REDIRECT_FORMAT, URLEncoder.encode(config.getPostLogoutURI(), "UTF-8"));
        }
        return LOG_OUT_URL_WITH_REDIRECT_FORMAT;
    }
}
