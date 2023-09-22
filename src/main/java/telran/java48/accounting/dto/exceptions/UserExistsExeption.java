package telran.java48.accounting.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UserExistsExeption extends RuntimeException{

	private static final long serialVersionUID = -3473632847256698244L;

}
