// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.certificate;

import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.Base64;

import static com.microsoft.azure.certificate.Constans.*;

/**
 * Helper class to load certificate from Key Vault using Managed Identity,
 * only PKCS12 format with RSA key is supported
 */
public class CertificateKeyVaultProvider {

    /**
     * User assigned managed identity client ID (as opposed to system assigned managed identity)
     * See https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-manage-ua-identity-portal.
     */
    private String userAssignedManagedIdentityClientId;
    private String keyVaultUrl;
    private String certificateName;

    private X509Certificate x509Certificate;
    private PrivateKey privateKey;

    public X509Certificate getX509Certificate()
            throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
        return getX509Certificate(false);
    }

    public X509Certificate getX509Certificate(boolean skipCache)
            throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
        if(skipCache || !validateCertificate()){
            getCertificateFromKeyVault();
        }
        return x509Certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    CertificateKeyVaultProvider(String keyVaultUrl, String certName){
        this.keyVaultUrl = keyVaultUrl;
        this.certificateName = certName;
    }

    public String getUserAssignedManagedIdentityClientId() {
        return userAssignedManagedIdentityClientId;
    }

    public void setUserAssignedManagedIdentityClientId(String userAssignedManagedIdentityClientId) {
        this.userAssignedManagedIdentityClientId = userAssignedManagedIdentityClientId;
    }

    /**
     * Load a certificate and  RSA Private Key from Key Vault.
     * @throws CertificateException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private void getCertificateFromKeyVault() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {

        DefaultAzureCredentialBuilder credentialBuilder = new DefaultAzureCredentialBuilder();
        if(StringUtils.isNoneBlank(userAssignedManagedIdentityClientId)){
            credentialBuilder.managedIdentityClientId(userAssignedManagedIdentityClientId);
        }
        DefaultAzureCredential credential = credentialBuilder.build();

        CertificateClient certificateClient = new CertificateClientBuilder()
                .vaultUrl(keyVaultUrl)
                .credential(credential)
                .buildClient();

        KeyVaultCertificateWithPolicy certificate = certificateClient.getCertificate(certificateName);

        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUrl)
                .credential(credential)
                .buildClient();

        if (certificate.getProperties().getNotBefore() == null || certificate.getProperties().getExpiresOn() == null)
        {
            return;
        }

        if(OffsetDateTime.now().isBefore(certificate.getProperties().getNotBefore()) ||
                OffsetDateTime.now().isAfter(certificate.getProperties().getExpiresOn() )){
            return;
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificate.getCer());
        x509Certificate = (X509Certificate)cf.generateCertificate(in);

        // Return a certificate with only the public key if the private key is not exportable.
        if (certificate.getPolicy() != null && !certificate.getPolicy().isExportable())
        {
            return;
        }

        // Parse the secret ID and version to retrieve the private key.
        String[] segments = certificate.getSecretId().split("/");

        if (segments.length != 3)
        {
            throw new IllegalStateException(String.format(
                    INCORRECT_NUMBER_OF_URI_SEGMENTS,
                    segments.length,
                    certificate.getSecretId()));
        }

        String secretName = segments[1];
        String secretVersion = segments[2];

        KeyVaultSecret secret = secretClient.getSecret(secretName, secretVersion);

        String secretContentType = secret.getProperties().getContentType();
        if(CONTENT_TYPE_PKSC_12.equalsIgnoreCase(secretContentType)){
            privateKey = LoadRsaKeyFromBase64Encoded(secret.getValue());
            return;
        }
        else {
            throw new UnsupportedOperationException(
                    String.format(
                            ONLY_PKCS_12_IS_SUPPORTED,
                            secretContentType));
        }
    }

    private static PrivateKey LoadRsaKeyFromBase64Encoded(String Base64EncodedKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedKey = Base64.getDecoder().decode(Base64EncodedKey);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(decodedKey);

        return kf.generatePrivate(keySpecPKCS8);
    }

    /**
     * Checks that the certificate is currently valid.
     * It is if the current date and time are within the validity period given in the certificate.
     * @return boolean value representing validity of certificate
     */
    private boolean validateCertificate(){
        if(x509Certificate == null){
            return false;
        }
        try {
            x509Certificate.checkValidity();
            return true;
        }
        catch (CertificateException e){
            return false;
        }
    }
}
