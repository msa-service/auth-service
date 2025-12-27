package msa.service.auth.config;

import msa.service.auth.domain.exception.BaseException;
import msa.service.auth.service.response.ErrorResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @Value("${product.level}")
    private String level;

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handleNotFoundException(BaseException e) {
        ErrorResponse errorResponse = ErrorResponse.from(e.getErrorCode(), e.getMessage());

        // error message format: {class_name}.{method_name}: ~~

        if (level.equalsIgnoreCase("DEV")) {
            errorResponse.setMessage(errorResponse.getMessage().split(":")[0].strip());
        }

        return ResponseEntity
                .status(e.getStatus())
                .body(errorResponse);
    }
}
