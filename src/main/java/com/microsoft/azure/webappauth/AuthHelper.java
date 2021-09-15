package com.microsoft.azure.webappauth;

import com.microsoft.aad.msal4j.IAuthenticationResult;

import javax.servlet.http.HttpServletRequest;

/**
 * Helper class to be used to simplify integration of
 * java mvc web applications with Microsoft Identity Platform
 */
public class AuthHelper {

    /**
     * Processing of auth code redirect request from identity provider includes:
     *  - validation of auth code redirect request
     *  - redeeming of auth code for auth tokens with identity provider
     *  - persistence of OIDC tokens and user credential in the user`s session
     * @param request auth code redirect request from identity provider
     */
    void processAuthCodeRedirectRequestStoreCredentialInSession(HttpServletRequest request){

    }

    /**
     * Check that current user`s session is authenticated,
     * which means that user`s credential is attached to the session
     * and it is not expired
     * @param request
     * @return boolean
     */
    boolean sessionAuthenticated(HttpServletRequest request){

        return false;
    }


    /**
     * Acquire access token for the scope from Microsoft identity platform
     * using user`s credential attached to the session
     * @param scope
     * @return
     */
    String getAccessToken(String scope){
        return null;
    }

    /**
     * Return user`s credential attached to the session
     * @return
     */
    IAuthenticationResult getCredential(){
        return null;
    }

    /**
     * Return authorization url to be used to redirect user to identity provider
     * to perform authorization
     * @return
     */
    String getAuthorizationUrl(){
        return null;
    }

    /**
     * Return authorization url to be used to redirect user to identity provider
     * to invalidate user`s session
     * @return
     */
    String getLogOutUrl(){
        return null;
    }

}
