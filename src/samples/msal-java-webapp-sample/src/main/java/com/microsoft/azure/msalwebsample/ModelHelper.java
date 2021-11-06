// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTParser;
import org.springframework.web.servlet.ModelAndView;

import java.text.ParseException;

public class ModelHelper {

    final static String TENANT_ID_CLAIM = "tid";

    static void setAccountInfo(ModelAndView model, IAuthenticationResult credential) throws ParseException {
        String tenantId = JWTParser.parse(credential.idToken()).getJWTClaimsSet().getStringClaim(TENANT_ID_CLAIM);

        model.addObject("tenantId", tenantId);
        model.addObject("account", credential.account());
    }
}
