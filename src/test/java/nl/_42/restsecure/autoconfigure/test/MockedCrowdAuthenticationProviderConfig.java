package nl._42.restsecure.autoconfigure.test;

import static java.util.Arrays.asList;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.atlassian.crowd.integration.soap.SOAPPrincipal;
import com.atlassian.crowd.integration.soap.springsecurity.user.UserWithAttributesAdapter;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;

import nl._42.restsecure.autoconfigure.CustomAuthenticationProviders;

@Configuration
public class MockedCrowdAuthenticationProviderConfig {

    @Bean
    public CustomAuthenticationProviders customAuthenticationProviders() {
        return new CustomAuthenticationProviders() {
            @Override
            public List<AuthenticationProvider> get() {
                return asList(new AuthenticationProvider() {

                    @Override
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        return new UsernamePasswordAuthenticationToken(
                                new CrowdUserDetails(
                                        new UserWithAttributesAdapter(new SOAPPrincipal("crowdUser")),
                                        asList(new SimpleGrantedAuthority("ROLE_USER"))),
                                "crowdPassword");
                    }

                    @Override
                    public boolean supports(Class<?> authentication) {
                        return true;
                    }

                });
            }
        };
    }
}
