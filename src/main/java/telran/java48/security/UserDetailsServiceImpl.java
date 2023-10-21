package telran.java48.security;

import java.time.LocalDate;
import java.util.Arrays;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java48.accounting.dao.UserAccountRepository;
import telran.java48.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	final UserAccountRepository userAccountRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserAccount userAccount = userAccountRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
		String[] roles = userAccount.getRoles()
				.stream()
				.map(r -> "ROLE_" + r.toUpperCase())
				.toArray(String[]::new);
		if(userAccount.getPasswordExpDate().isBefore(LocalDate.now())) {
			roles = Arrays.copyOf(roles, roles.length + 1);
            roles[roles.length - 1] = "ROLE_PASSWORD_EXPIRED";
		}
		return new User(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles));
	}

}
