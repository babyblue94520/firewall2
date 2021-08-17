package pers.clare.firewall;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import({FirewallConfiguration.class})
@Configuration
public @interface EnableFirewall {
    @AliasFor(
            annotation = Configuration.class
    )
    String value() default "";
}
