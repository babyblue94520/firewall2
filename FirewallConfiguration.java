package pers.clare.firewall;

//import org.springframework.beans.factory.InitializingBean;
//import org.springframework.boot.context.properties.ConfigurationProperties;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 產生防火牆規則服務.
 */
@Configuration
@ConfigurationProperties(prefix = "firewall")
public class FirewallConfiguration {

    @NestedConfigurationProperty
    private FirewallProperties rule;

    @NestedConfigurationProperty
    private FirewallProperties additionalRule;

    public void setRule(FirewallProperties rule) {
        this.rule = rule;
    }

    public void setAdditionalRule(FirewallProperties additionalRule) {
        this.additionalRule = additionalRule;
    }

    public FirewallProperties getRule() {
        return rule;
    }

    public FirewallProperties getAdditionalRule() {
        return additionalRule;
    }

    @Bean
    public FirewallService firewallService() {
        FirewallService firewallService = new FirewallService();
        if (rule != null) {
            firewallService.addRules(rule);
        }
        if (additionalRule != null) {
            firewallService.addRules(rule);
        }
        return firewallService;
    }
}
