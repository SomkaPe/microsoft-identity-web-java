// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;
import com.microsoft.azure.webappauth.AuthHelper;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter(urlPatterns = "/msal4jsample/secure/aad")
public class AadAuthFilter implements Filter {

    @Autowired
    private AuthHelper authHelper;

    /**
     * Verify the session is authenticated - valid not expired credential attached to the session.
     **/
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!authHelper.isSessionAuthenticated(httpRequest)) {
            httpResponse.sendRedirect("/msal4jsample/login");
            return;
        }
        chain.doFilter(request, response);
    }
}
