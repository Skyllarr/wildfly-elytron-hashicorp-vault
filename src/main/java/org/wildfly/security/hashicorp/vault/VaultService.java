/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.jboss.logging.Logger;

public class VaultService {

    private static final Logger logger = Logger.getLogger(VaultService.class);

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final boolean sslVerify;
    private final SslConfig sslConfig;

    private Vault vault;
    private final Map<String, Object> secretCache = new ConcurrentHashMap<>();

    public VaultService(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslVerify = sslVerify;
        this.sslConfig = sslConfig;
    }

    public void start() {
        try {
            VaultConfig config = new VaultConfig()
                    .sslConfig(sslConfig)
                    .address(vaultUrl)
                    .token(token);
            SslConfig sslConfig = config.getSslConfig();

            if (sslConfig != null) {
                sslConfig.verify(sslVerify);
            }

            if (namespace != null && !namespace.isEmpty()) {
                config.nameSpace(namespace);
            }

            vault = Vault.create(config);

            // Test connection
            vault.auth().lookupSelf();

            logger.infof("Vault service started successfully, connected to: %s", vaultUrl);

        } catch (VaultException ignored) {

        }
    }


    /**
     * Retrieve a secret from Vault
     */
    public String getSecret(String path, String key) throws VaultException {
        String cacheKey = path + ":" + key;

        // Check cache first
        Object cachedValue = secretCache.get(cacheKey);
        if (cachedValue != null) {
            return (String) cachedValue;
        }

        // Fetch from Vault
        LogicalResponse response = vault.logical().read(path);
        if (response.getRestResponse().getStatus() == 200) {
            Map<String, String> data = response.getData();
            String value = data.get(key);

            // Cache the value
            if (value != null) {
                secretCache.put(cacheKey, value);
            }

            return value;
        }

        throw new VaultException("Secret not found: " + path + "/" + key);
    }
}
