// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;

import com.microsoft.azure.webappauth.AuthHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class AuthController {

    @Autowired
    AuthHelper authHelper;

    @RequestMapping("/msal4jsample/login")
    public void login(HttpServletRequest httpRequest, HttpServletResponse response)
            throws IOException {

        response.sendRedirect(authHelper.getAuthorizationUrl(httpRequest));
    }

    @RequestMapping("/msal4jsample/logout")
    public void logout(HttpServletRequest httpRequest, HttpServletResponse response)
            throws IOException {

        httpRequest.getSession().invalidate();

        response.sendRedirect(authHelper.getLogOutUrl());
    }

    /**
     * Process a call to the redirect_uri with a GET HTTP method
     */
    @RequestMapping("/msal4jsample/auth-code-redirect")
    public ModelAndView processAuthCodeRedirect(HttpServletRequest httpRequest, HttpServletResponse response) {
        ModelAndView mav;
        try {
            authHelper.processAuthCodeRedirectRequest(httpRequest);
            mav = new ModelAndView("auth_page");
            ModelHelper.setAccountInfo(mav, authHelper.getCredential(httpRequest));
        } catch (Throwable e) {
            mav = new ModelAndView("error");
            mav.addObject("error", e);
        }
        return mav;
    }
}
