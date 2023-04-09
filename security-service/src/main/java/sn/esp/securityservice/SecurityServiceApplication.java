package sn.esp.securityservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import sn.esp.securityservice.configuration.RsakeysConfig;

@SpringBootApplication
@EnableConfigurationProperties(RsakeysConfig.class) // processor : public record RsakeysConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }
    
}
