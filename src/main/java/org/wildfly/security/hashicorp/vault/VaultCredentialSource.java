/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Supplier;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

public class VaultCredentialSource implements CredentialSource {

    private final VaultService vaultService;
    private final String secretPath;
    private final String secretKey;

    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };

    public VaultCredentialSource(VaultService vaultService, String secretPath, String secretKey) {
        this.vaultService = vaultService;
        this.secretPath = secretPath;
        this.secretKey = secretKey;
    }

    // xxx check this later
    public boolean isCredentialSupported(Class<? extends Credential> credentialType, String algorithm,
                                         AlgorithmParameterSpec parameterSpec) throws IOException {
        return credentialType == PasswordCredential.class &&
                (algorithm == null || ClearPassword.ALGORITHM_CLEAR.equals(algorithm))
                ? true : false;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithm,
                                                  AlgorithmParameterSpec parameterSpec) throws IOException {

        if (credentialType == PasswordCredential.class) {
            try {
                String password = vaultService.getSecret(secretPath, secretKey);
                if (password != null) {
                    PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
                    ClearPassword clearPassword = (ClearPassword) factory.generatePassword(
                            new ClearPasswordSpec(password.toCharArray()));
                    return credentialType.cast(new PasswordCredential(clearPassword));
                }
            } catch (Exception e) {
                throw new IOException("Failed to retrieve credential from Vault", e);
            }
        }

        return null;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                                                    AlgorithmParameterSpec parameterSpec) throws IOException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getCredentialAcquireSupport'");
    }
}