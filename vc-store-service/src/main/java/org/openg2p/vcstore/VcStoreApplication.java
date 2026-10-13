package org.openg2p.vcstore;

import org.openg2p.vcstore.config.VaultProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(VaultProperties.class)
public class VcStoreApplication {
    public static void main(String[] args) {
        SpringApplication.run(VcStoreApplication.class, args);
    }
}
