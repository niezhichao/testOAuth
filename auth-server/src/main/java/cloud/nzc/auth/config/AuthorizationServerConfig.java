package cloud.nzc.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private  BCryptPasswordEncoder passwordEncoder;
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        String secret=passwordEncoder.encode("secret");
        System.out.println(secret);
        clients.inMemory()
        .withClient("client")
        .secret(secret)
        .authorizedGrantTypes("authorization_code")
        .scopes("app")
        .redirectUris("http://www.funtl.com");
    }

}
