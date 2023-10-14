package telran.java48.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;
import telran.java48.post.dao.PostRepository;

@Configuration
@RequiredArgsConstructor
public class AuthorizationConfiguration {
	final PostRepository postRepository;

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic(Customizer.withDefaults());
		http.csrf(csrf -> csrf.disable());
		http.authorizeRequests(authorize -> authorize
			.mvcMatchers("/account/register", "/forum/posts/**")
				.permitAll()
			.mvcMatchers("/account/user/{login}/role/{role}")
				.hasRole("ADMINISTRATOR")
			.mvcMatchers(HttpMethod.PUT, "/account/user/{login}", "/forum/post/{id}/comment/{author}")
				.access("#login == authentication.name || #author == authentication.name")
			.mvcMatchers(HttpMethod.POST, "/forum/post/{author}")
				.access("#author == authentication.name")
			.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}")
				.access("#login == authentication.name or hasRole('ADMINISTRATOR')")
			.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}")
				.access("@postRepository.findById(#id).orElse(null)?.author == authentication.name or hasRole('MODERATOR')")
			.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}")
				.access("@postRepository.findById(#id).orElse(null)?.author == authentication.name")
			.anyRequest()
				.authenticated());   
		return http.build();
	}
}
