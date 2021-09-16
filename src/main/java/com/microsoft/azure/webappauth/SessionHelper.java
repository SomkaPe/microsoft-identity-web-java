// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.webappauth;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import jdk.internal.joptsimple.internal.Strings;

import javax.servlet.http.HttpSession;

import static com.microsoft.azure.webappauth.Constants.FAILED_TO_VALIDATE_MESSAGE;

public class SessionHelper {

    static final String PRINCIPAL_SESSION_NAME = "aad_auth_principal";
    static final String TOKEN_CACHE_SESSION_ATTRIBUTE = "aad_auth__token_cache";
    static final String STATE = "aad_auth_state";
    static final String NONCE = "aad_auth_nonce";

    static void addStateNonceToSession(HttpSession session, String state, String nonce) {

        // used to prevent CSRF attacks - make sure that auth code response matches with auth request
        session.setAttribute(STATE, state);

        // used to prevent reply attack - make sure id token matches auth request
        session.setAttribute(NONCE, nonce);
    }

    static void validateState(HttpSession session, String state) throws Exception {
        String sessionState = (String) session.getAttribute(STATE);

        // session`s state should not used more than once
        session.removeAttribute(STATE);

        if(Strings.isNullOrEmpty(sessionState)){
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate state, missing session`s state");
        }

        if (!sessionState.equals(state)) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate state, request response states do not match");
        }
    }

    static void validateNonce(HttpSession session, String nonce) throws Exception {
        String sessionNonce = (String) session.getAttribute(NONCE);

        // session`s nonce should not used more than once
        session.removeAttribute(NONCE);

        if(Strings.isNullOrEmpty(sessionNonce)){
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce, missing session`s nonce");
        }

        if (!sessionNonce.equals(nonce)) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce, request response nonces do not match");
        }
    }

    static void setTokenCache(HttpSession session, String tokenCache){
        session.setAttribute(TOKEN_CACHE_SESSION_ATTRIBUTE, tokenCache);
    }

    static String getTokenCache(HttpSession session){
        return (String)session.getAttribute(TOKEN_CACHE_SESSION_ATTRIBUTE);
    }

    static void setSessionPrincipal(HttpSession session, IAuthenticationResult result) {
        session.setAttribute(PRINCIPAL_SESSION_NAME, result);
    }

    static IAuthenticationResult getSessionPrincipal(HttpSession session) {
        return (IAuthenticationResult)session.getAttribute(PRINCIPAL_SESSION_NAME);
    }

    static void logOut(HttpSession session) {
        session.removeAttribute(PRINCIPAL_SESSION_NAME);
        session.removeAttribute(TOKEN_CACHE_SESSION_ATTRIBUTE);

        session.removeAttribute(STATE);
        session.removeAttribute(NONCE);
    }
}
