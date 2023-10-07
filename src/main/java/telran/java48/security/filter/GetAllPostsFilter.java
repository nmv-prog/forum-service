package telran.java48.security.filter;

import java.io.IOException;
import java.util.List;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import lombok.RequiredArgsConstructor;
import telran.java48.post.dao.PostRepository;
import telran.java48.post.model.Post;

@Component
@RequiredArgsConstructor
@Order(1)
public class GetAllPostsFilter implements Filter {
	final PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			List<Post> allPosts = postRepository.findAll();
			
			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.registerModule(new JavaTimeModule());
	        String jsonPosts = objectMapper.writeValueAsString(allPosts);
	        
	        response.setContentType("application/json");
	        response.setCharacterEncoding("UTF-8");
	        response.getWriter().write(jsonPosts);
	        response.getWriter().flush();
			return;
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		return (HttpMethod.GET.matches(method) || HttpMethod.POST.matches(method)) && path.matches("/forum/posts/?");
	}

}
