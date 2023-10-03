package telran.java48.security.filter;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java48.accounting.dao.UserAccountRepository;
import telran.java48.accounting.model.UserAccount;
import telran.java48.post.dao.PostRepository;
import telran.java48.post.model.Post;

@Component
@RequiredArgsConstructor
@Order(40)
public class DeleteUserOrPostFilter implements Filter {
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			Principal principal = request.getUserPrincipal();
			String[] arr = request.getServletPath().split("/");
			String id = arr[arr.length - 1];
			UserAccount userAccount = userAccountRepository.findById(principal.getName()).get();

			if (arr[1].equalsIgnoreCase("account")) {
				if (!principal.getName().equalsIgnoreCase(id)) {
					if (!userAccount.getRoles().contains("ADMINISTRATOR")) {
						response.sendError(403, "Permission denied");
						return;
					}
				}
			}

			if (arr[1].equalsIgnoreCase("forum")) {
				Post post = postRepository.findById(id).get();
				if (!principal.getName().equalsIgnoreCase(post.getAuthor())) {
					if (!userAccount.getRoles().contains("MODERATOR")) {
						response.sendError(403, "Permission denied");
						return;
					}
				}
			}

		}
		chain.doFilter(request, response);

	}

	private boolean checkEndPoint(String method, String path) {
		return HttpMethod.DELETE.matches(method)
				&& (path.matches("/account/user/\\w+/?") || path.matches("/forum/post/\\w+/?"));
	}

}
